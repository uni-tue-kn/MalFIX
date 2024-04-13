#! /usr/bin/env python
## ------------------------------------------------------------------------
## sample_exporter_collector_blind.py
##
## sample IPFIX collector & exporter (aka mediator) using pyfixbuf.
## created to be used with the sample_exporter.py script.
## Processes the ipfix file created by sample_exporter.py and writes
## to a text file.  This is different from sample_exporter_collector.py
## in that it has no idea what to expect.
## ------------------------------------------------------------------------
## Copyright (C) 2013-2022 Carnegie Mellon University. All Rights Reserved.
## ------------------------------------------------------------------------
## Authors: Emily Sarneso
## ------------------------------------------------------------------------
## See license information in LICENSE-OPENSOURCE.txt

from __future__ import print_function
import os
import sys
import pyfixbuf
import pyfixbuf.cert

# create the information model with the standard IPFIX elements
infomodel = pyfixbuf.InfoModel()

# add YAF's elements
pyfixbuf.cert.add_elements_to_model(infomodel)

# create the session
session = pyfixbuf.Session(infomodel)

# define the callback function invoked when the session sees a new
# template; arguments are the Session, the Template, and an unused
# object for the context
#
def new_template_callback(s, t, c):
    tid = t.template_id
    new_tmpl = pyfixbuf.Template(infomodel)
    for spec in t:
        new_tmpl.add_spec(spec)
    s.add_internal_template(new_tmpl, tid)
    print("callback added template to session: %d %s" % (tid, str(new_tmpl)))

# add the callback
session.add_template_callback(new_template_callback)

# create a listener
listener = pyfixbuf.Listener(session, hostname="localhost", port=18001)

# open the output file
if (len(sys.argv) > 4):
    outFile = open(sys.argv[4], "w")
else:
    outFile = sys.stdout

flowcount = 0

dontprintlist=["subTemplateMultiList", "subTemplateList", "paddingOctets"]
buf = None
template_id = -1

while listener:
    if not buf:
        #print("getting a buf")
        buf = listener.wait()

    try:
        #print("getting a template")
        tmpl_next = buf.next_template()
    except StopIteration:
        #print("stop iter getting template")
        buf = None
        continue

    #print(tmpl_next.template_id, tmpl_next)
    if tmpl_next.template_id != template_id:
        # Set a new template and record for the Buffer
        template_id = tmpl_next.template_id
        tmpl = session.get_template(template_id, True)
        rec = pyfixbuf.Record(infomodel, tmpl)
        buf.set_internal_template(template_id)
        buf.set_record(rec)

    try:
        #print("getting data")
        data = next(buf)
    except StopIteration:
        #print("stop iter getting data")
        buf = None
        continue

    if data:
        for field in data.iterfields():
            if (field.name not in dontprintlist):
                outFile.write(field.name + ": " + str(field.value) + "\n")

        if "subTemplateMultiList" in data:
            stml = data["subTemplateMultiList"]
            subs = 0
            for entry in stml:
                outFile.write("--- STML %d ---\n" % subs)
                recs = 0
                for record in entry:
                    x = 0
                    outFile.write("-- ENTRY %d --\n" % recs)
                    for field in record.iterfields():
                        outFile.write(field.name + ": " + str(field.value) + "\n")
#                    for elem in record:
#                        if type(elem) is pyfixbuf.STL:
#                            for item in elem:
#                                for f in item.iterfields():
#                                    outFile.write(f.name + ": " + str(f.value) + "\n")
#                            elem.clear()
#                        elif type(elem) is pyfixbuf.BL:
#                            count = 0
#                            for item in elem:
#                                outFile.write(elem.element.name + " " + str(count) + " is " + item + "\n")
#                                count += 1
#                            elem.clear()
#                        else:
#                            outFile.write("Item " + str(x) + ": " + str(elem) + "\n")
                        x += 1
                recs += 1
            subs += 1

            stml.clear()

        flowcount += 1
    # get data out of STML
        outFile.write("------------------------------\n")

sys.stdout.write("Processed " + str(flowcount) + " flows \n")