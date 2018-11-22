#
# To extract information of API while program is running
# Use various introspection capabilities available in python
# Creates one plain text file into the home directory
# Copyright 2018 Maria Andrea Vignau

# IMPORTANT: Autopsy don't reload secondary modules every time
# runs it, e.g. imported modules stays in memory. In order to
# reload it on debug o refactoring, you must restart Autopsy itself.

import os

class apiReference():
    def __init__(self, debug = False):
        self.debug = debug
        self.filename = ""
        if self.debug:
            idx = 0
            while True:
                self.filename = os.path.join(os.path.expanduser("~"), "AutopsyAPIv%04d.txt" %idx)
                if not os.path.exists(self.filename):
                    break
                idx += 1
            self.reported = []

    def apireport(self, object):
        if self.debug:
            fn = open(self.filename, "a")
            try:
                classname = object.__class__.__name__
                if not classname in self.reported:
                    fn.write("\n== " + classname + "  == \n  ")
                    members = []
                    for member in dir(object):
                        content = repr(getattr(object, member))
                        if len(content) > 80:
                            content = content[:78] + " ..."
                        members.append(u"%s : %s" % (member, content))
                    members = '\n  '.join(members)
                    fn.write(members + "\n----------------\n\n")
                    if "toString" in dir(object):
                        fn.write(">>> " + object.toString() + "\n\n")
                    self.reported.append(classname)
                else:
                    fn.write(".")

            finally:
                fn.close()