#include <pcap.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <syslog.h>
#include <libxml/xpath.h>
#include <libvirt/libvirt.h>

char *device = NULL;
char *password = NULL;
char *connection_uri = NULL;

void print_usage(char *arg) {
    printf("Usage: %s -d <device> [-p <password>] [-c <connection-uri>]\n", arg);
}

int parse_args(int argc, char **argv)
{
    int opt = 0;

    static struct option long_options[] = {
        {"connection-uri", required_argument, 0,  'c' },
        {"password",       required_argument, 0,  'p' },
        {"device",         required_argument, 0,  'd' },
        {0,                0,                 0,  0   }
    };

    int long_index =0;
    while ((opt = getopt_long(argc, argv,"c:p:d:", 
                   long_options, &long_index )) != -1) {
        switch (opt) {
             case 'c' : connection_uri = optarg;
                 break;
             case 'p' : password = optarg;
                 break;
             case 'd' : device = optarg;
                 break;
             default: print_usage(argv[0]); 
                 exit(EXIT_FAILURE);
        }
    }

    if (device == NULL) {
        return 1;
    }

    return 0;
}

int find_domain_by_xml_entry(char *xmlString, char *xPath, char *match)
{
    xmlDocPtr doc;
    xmlParserCtxtPtr pctxt;
    xmlXPathContextPtr context;
    xmlXPathObjectPtr op;
    xmlNodeSetPtr nodeset;
    int i, num, ret;

    ret = 0;
    pctxt = xmlCreateDocParserCtxt((xmlChar *)xmlString);
    doc = xmlCtxtReadDoc(pctxt, (xmlChar *)xmlString, NULL, NULL, XML_PARSE_NOWARNING | XML_PARSE_NOERROR);
    context = xmlXPathNewContext(doc);
    op = xmlXPathEvalExpression( (xmlChar *)xPath, context);
    xmlXPathFreeContext(context);
    if (xmlXPathNodeSetIsEmpty(op->nodesetval)){
        xmlXPathFreeObject(op);
        return 1;
    }

    nodeset = op->nodesetval;
    num = nodeset->nodeNr;

    for (i = 0; i < num; i++) {
        char *data = (char *)xmlNodeListGetString(doc, (nodeset->nodeTab[i])->xmlChildrenNode, 1);
        ret = (strcmp(data, match) == 0);
    }

    xmlXPathFreeObject(op);

    xmlFreeDoc(doc);
    xmlCleanupParser();
    return ret;
}

int domain_start(char *mac_address)
{
    int ret, i, j;
    int retval = 0;
    virConnectPtr cptr;
    virDomainPtr *domains;

    cptr = virConnectOpen(NULL);
    ret = virConnectListAllDomains(cptr, &domains, VIR_CONNECT_LIST_DOMAINS_INACTIVE);
    for (i = 0; i < ret; i++) {
	char *xml = virDomainGetXMLDesc(domains[i], 0);
        if (find_domain_by_xml_entry(xml, "//domain/devices/interface/mac/@address", mac_address)) {
            if (virDomainCreate(domains[i]) == 0) {
                retval++;
            }
        }
	virDomainFree(domains[i]);
        free(xml);
    }
    virConnectClose(cptr);
    return retval;
}

void pkt_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body)
{
    if (packet_header->len < 15) {
        return;
    }

    // Check whether it is WoL packet
    if ((packet_body[12] == 0x08) && (packet_body[13] == 0x42)) {
        char src_mac[18];
        char req_mac[18];
        char dst_mac[18];
        char pwd[18];

        memset(pwd, 0, sizeof(pwd));
        snprintf(req_mac, sizeof(req_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
            packet_body[0], packet_body[1], packet_body[2],
            packet_body[3], packet_body[4], packet_body[5]);

        snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
            packet_body[6], packet_body[7], packet_body[8],
            packet_body[9], packet_body[10], packet_body[11]);

        snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
            packet_body[14], packet_body[15], packet_body[16],
            packet_body[17], packet_body[18], packet_body[19]);

        if (packet_header->len > 116) {
            if (packet_header->len == 120) {
                snprintf(pwd, sizeof(pwd), "%d.%d.%d.%d", packet_body[116], packet_body[117], packet_body[118], packet_body[119]);
            }
            if (packet_header->len == 122) {
                snprintf(pwd, sizeof(pwd), "%02x:%02x:%02x:%02x:%02x:%02x", packet_body[116], packet_body[117], packet_body[118], packet_body[119], packet_body[120], packet_body[121]);
            }
        }

        if (strcmp(dst_mac, "ff:ff:ff:ff:ff:ff") == 0) {
            int is_ok = 1;
            if ((password != NULL) && (strcmp(pwd, password) != 0)) {
                is_ok = 0;
            }

//            printf(">>> SRC_MAC '%s', REQ_MAC: '%s', DST_MAC: '%s', PWD: '%s', PASSWORD: '%s', IS_OK: %d\n", src_mac, req_mac, dst_mac, pwd, password, is_ok);

            if (is_ok == 1) {
                int dom_cnt = domain_start(req_mac);
                syslog(LOG_INFO, "Received a Wake-on-Lan packet from '%s' to start up guest with MAC address '%s'. Started %d domain(s)...", src_mac, req_mac, dom_cnt);
            }
            else {
                syslog(LOG_INFO, "Received a Wake-on-Lan packet from '%s' to start up guest with MAC address '%s' but password was incorrect", src_mac, req_mac);
            }
        }
    }
}

int watch_for_packet(char *device) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(device, BUFSIZ, 1, 0, error_buffer);
    if (handle == NULL) {
         fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
         return 1;
     }

    pcap_loop(handle, 0, pkt_handler, NULL);
    pcap_close(handle);

    return 0;
}

void exit_handler(void) {
    closelog();
}

int main(int argc, char *argv[])
{
    if (parse_args(argc, argv) != 0) {
        fprintf(stderr, "Error: Interface name to check for WoL packet is missing\n");
        return 1;
    }

    openlog("libvirt-wol", LOG_PID|LOG_CONS, LOG_USER);
    atexit(exit_handler);
    if (fork() == 0) {
        return watch_for_packet(device);
    }
    else {
        return 0;
    }
}

