# subTemplateMultiList -> subTemplateList -> subTemplateList
#                         dnsName               IPv4
from numbers import Number
from typing import Tuple

print_debug = False


def extract_dns_info(data) -> Tuple[str, Number]:
    if "subTemplateMultiList" in data:
        stml = data["subTemplateMultiList"]
        for entry in stml:
            for record in entry:
                if "subTemplateList" in record:
                    stl = record["subTemplateList"]
                    for dns_record in stl:
                        if "dnsName" in dns_record:
                            dns_name = dns_record["dnsName"]
                            query_type = dns_record["dnsRRType"]
                            dns_query_response = dns_record["dnsQueryResponse"]
                            if dns_query_response == 1:
                                if print_debug:
                                    print("Response with type " + str(query_type) + " and name " + dns_name)
                                dns_response_list = dns_record["subTemplateList"]
                                for dns_response in dns_response_list:
                                    if query_type == 1:
                                        if print_debug:
                                            print(dns_response["sourceIPv4Address"])
                                    if query_type == 28:
                                        if print_debug:
                                            print(dns_response["sourceIPv6Address"])
                            else:
                                if print_debug:
                                    print("Query with type " + str(query_type) + " and name " + dns_name)
                                return dns_name, 4 if query_type == 1 else 6
    return "", 0
