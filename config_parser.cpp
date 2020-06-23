#include "dytan.h"
#include "config_parser.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <errno.h>

//parses sources in the configuration file
void parseSources(xmlDocPtr doc, xmlNodePtr cur, config *conf)
{
    xmlChar *txt, *subtext;
    xmlNodePtr sub;
    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if((!xmlStrcmp(cur->name, (const xmlChar *)"source"))) {
            source src;
            txt = xmlGetProp ( cur, (const xmlChar *)"type" );
            if (txt) {
                log << "sources type = " << txt << ":\n";
                log.flush();
                string type((char *)txt);
                src.type = type;
                xmlFree( txt );
                sub = cur->xmlChildrenNode;
                while (sub != NULL) {
                    if (sub->type == XML_ELEMENT_NODE) {
                        log << "\t\t " << sub->name << ": ";
                        subtext = xmlNodeListGetString(doc, sub->xmlChildrenNode, 1);
                        log << subtext << "\n";
                        log.flush();
                        if(!xmlStrcmp(sub->name, (const xmlChar *)"granularity")) {
                            string granularity((char *)subtext);
                            src.granularity = granularity;
                        } else {
                            string details((char *)subtext);
                            src.details.push_back(details);
                        }
                        xmlFree(subtext);
                    }
                    sub = sub->next;
                }
            }
            else {
                fprintf(stderr, "Sources: Document not structured properly");
            }
            conf->sources.push_back(src);
        } else if ((!xmlStrcmp(cur->name, (const xmlChar *)"taint-marks"))) {
            txt = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            log << "max taint marks = " << txt << "\n";
            log.flush();
            string num_markings((const char *)txt);
            conf->num_markings = num_markings;
            xmlFree(txt);
        }
        cur = cur->next;
    }
}

//parses profiling info in the configuration file
void parsePropagation(xmlDocPtr doc, xmlNodePtr cur, config *conf)
{
    xmlChar *key;
    propagation prop;
    prop.dataflow = false;
    prop.controlflow = false;
    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
	if((!xmlStrcmp(cur->name, (const xmlChar *)"dataflow"))) {
	    key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
	    log << "dataflow :" <<key << "\n";
            prop.dataflow = (!strcmp((char *)key, "true") ? true: false);
	    xmlFree(key);
	}
        else if ((!xmlStrcmp(cur->name, (const xmlChar *)"controlflow"))) {
	    key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            log << "controlflow :" << key << "\n";
            prop.controlflow = (!strcmp((char *)key, "true") ? true: false);
	    xmlFree(key);
	}
	cur = cur->next;
    }
    conf->prop = prop;
}

//parses profiling info in the configuration
void parseProfiling(xmlDocPtr doc, xmlNodePtr cur, config *conf)
{
    xmlChar *key;
    profiling prof;
    prof.marks = false;
    prof.markop = false;
    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
	if((!xmlStrcmp(cur->name, (const xmlChar *)"marks"))) {
	    key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
	    log << "marks :" <<key << "\n";
            prof.marks = (!strcmp((char *)key, "true") ? true: false);
	    xmlFree(key);
	}
	if((!xmlStrcmp(cur->name, (const xmlChar *)"markop"))) {
		key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
		log << "markop :" <<key << "\n";
		prof.markop = (!strcmp((char *)key, "true") ? true: false);
		xmlFree(key);
	}
	cur = cur->next;
    }
    conf->prof = prof;
}

//parses sinks in the configuration file
void parseSinks(xmlDocPtr doc, xmlNodePtr cur, config *conf)
{
    xmlChar *txt;
    xmlNodePtr sub, subsub;
    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if((!xmlStrcmp(cur->name, (const xmlChar *)"sink"))) {
            sub = cur->xmlChildrenNode;
            while (sub != NULL) {
                if  ((!xmlStrcmp(sub->name, (const xmlChar *)"id"))) {
                    txt = xmlNodeListGetString(doc, sub->xmlChildrenNode, 1);
                    log << "\nid = " << txt << "\n";
                    xmlFree(txt);
                } else if (!xmlStrcmp(sub->name, (const xmlChar *)"location")) {
                    txt = xmlGetProp( sub, (const xmlChar *)"type");
                    if (txt) {
                        log << "location type = " << txt << ":\n";
                        xmlFree( txt );
                        subsub = sub->xmlChildrenNode;
                        while (subsub != NULL) {
                            if (subsub->type == XML_ELEMENT_NODE) {
                                log << "\t\t " << subsub->name << " ";
                                txt = xmlNodeListGetString(doc, subsub->xmlChildrenNode, 1);
                                log << txt << "\n";
                                xmlFree(txt);
                            }
                            subsub = subsub->next;
                        }
                    }
                }
                sub = sub->next;
            }
        }
        cur = cur->next;
    }
}

#define CONFIGFILE "config.xml"

//parse XML configuration file using libxml2
int parseConfig( int argc, char **argv, config *conf ){

    xmlDocPtr doc;
    xmlNodePtr cur, sub;

    if( !(doc = xmlParseFile( CONFIGFILE ) ) ){
        fprintf( stderr, "Configuration file could not be parsed. It must be present in CURRENT DIRECTORY.\n" );
        xmlFreeDoc( doc );
        return( -1 );
    }

    if( !(cur = xmlDocGetRootElement( doc ) ) ){
        fprintf( stderr, "Configuration file has no root element.\n" );
        xmlFreeDoc( doc );
        return( -1 );
    }
    if( xmlStrcmp( cur->name, (const xmlChar *) "dytan-config" ) ){
        fprintf( stderr, "Configuration file of the wrong type, root node != dytan-config\n" );
        xmlFreeDoc( doc );
        return( -1 );
    }

    sub = cur->children;
    while( sub != NULL ){
        if( (!xmlStrcmp(sub->name, (const xmlChar *)"sources" ) ) ){
            parseSources(doc, sub, conf);
        }
        else if( (!xmlStrcmp(sub->name, (const xmlChar *)"propagation" ) ) ) {
	    parsePropagation(doc, sub, conf);
        }
        else if( (!xmlStrcmp(sub->name, (const xmlChar *)"sinks" ) ) ) {
            parseSinks(doc, sub, conf);
        }
        else if( (!xmlStrcmp(sub->name, (const xmlChar *)"profiling" ) ) ) {
        	parseProfiling(doc, sub, conf);
        }
        sub = sub->next;
    }

    log.flush();
    xmlFreeDoc( doc );
    return 0;
}
