# Sample module in the public domain. Feel free to use this as a template
# for your modules (and you can remove this header and take complete credit
# and liability)
#
# Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# See http://sleuthkit.org/autopsy/docs/api-docs/4.4/index.html for documentation

# Simple report module for Autopsy.
# Used as part of Python tutorials from Basis Technology - September 2015
#
# Writes a CSV file with all file names and MD5 hashes.



import os
import sys
import codecs
import inspect
from java.lang import System
from java.io import File
from java.util.logging import Level
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.casemodule \
    import Case
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.report import GeneralReportModuleAdapter
from org.sleuthkit.autopsy.report.ReportProgressPanel import ReportStatus
from org.sleuthkit.autopsy.report.ReportProgressPanel import ReportStatus
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel \
    import ContentUtils

import ConfigParser
import ApiHelper




class Config(object):
    def getConfig(self, section, option, default=None):
        try:
            result = self.config.get(section, option)
        except ConfigParser.Error:
            result = default
        return result

    def __init__(self, baseReportDir):
        self.config = ConfigParser.ConfigParser()
        self.config.read(os.path.join(os.path.dirname(__file__),'config.ini'))
        self.report_path  = self.getConfig("PATHS", "report_path", baseReportDir)
        if not self.report_path:
            self.report_path = baseReportDir
        self.output_path  = self.getConfig("PATHS", "output_path", baseReportDir)
        if not self.output_path:
            self.output_path = baseReportDir

        self.excluded_MimeTypes = self.getConfig("OUTPUT", "exclude", "")
        self.excluded_MimeTypes = [str(x).strip() for x in self.excluded_MimeTypes.split(",")]
        try:
            self.other = self.config.getboolean("OUTPUT", "other")
        except ConfigParser.Error:
            self.other = True




# Class responsible for defining module metadata and logic
class NotKnownBackup(GeneralReportModuleAdapter):

    moduleName = "Copy Not Known Files"

    _logger = None
    def log(self, level, msg):
        if self._logger == None:
            self._logger = Logger.getLogger(self.moduleName)
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def getName(self):
        return self.moduleName

    def getDescription(self):
        return "Copy Not Known Files, writes CSV of file names and hash values"

    def getRelativeFilePath(self):
        return "hashes.csv"

    # TODO: Update this method to make a report
    # The 'baseReportDir' object being passed in is a string with the directory that reports are being stored in.   Report should go into baseReportDir + getRelativeFilePath().
    # The 'progressBar' object is of type ReportProgressPanel.
    #   See: http://sleuthkit.org/autopsy/docs/api-docs/4.4/classorg_1_1sleuthkit_1_1autopsy_1_1report_1_1_report_progress_panel.html
    def generateReport(self, baseReportDir, progressBar):
        config = Config(baseReportDir)
        # Open the output file.
        fileName = os.path.join(config.report_path, self.getRelativeFilePath())
        excluded_filepath = os.path.join(config.report_path, "excluded_files.csv")

        # Declare the use of UTF8, necessary to write correct unicode names
        report = codecs.open(fileName, 'w', "utf8")
        excluded_files = codecs.open(excluded_filepath, 'w', "utf8")
        # apiref = ApiHelper.apiReference(True)   # use introspection to see object structure and content

        # Query the database for the files (ignore the directories)
        sleuthkitCase = Case.getCurrentCase().getSleuthkitCase()
        files = sleuthkitCase.findAllFilesWhere("NOT meta_type = " + str(TskData.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getValue()))
        MAX_NUMBER_FILES = len(files) + 1 # enable when finish tests
        # MAX_NUMBER_FILES = 50 # to speedup test process

        # Setup the progress bar
        progressBar.setIndeterminate(False)
        progressBar.start()
        progressBar.setMaximumProgress(MAX_NUMBER_FILES)
        self.log(Level.INFO, "Initial number of files to copy: %d" % MAX_NUMBER_FILES)

        if not os.path.exists(config.output_path):
            os.mkdir(config.output_path)

        defaultcontentDir = os.path.join(config.output_path, "Other")
        excluded_files.write("Excluded mime types:, %s\n" % repr(config.excluded_MimeTypes))
        excluded_files.write("Include no standard files:, %s, files w/o identified Mime\n" % str(config.other))

        if not os.path.exists(defaultcontentDir):
            os.mkdir(defaultcontentDir)
        line = ["MIME Type", "File Name", "Path", "Id", "MD5 Hash"]
        header = ','.join([str(x) for x in line]) + "\n"
        report.write(header)
        excluded_files.write(header)

        for idx, file in enumerate(files):
            if MAX_NUMBER_FILES and idx > MAX_NUMBER_FILES:
                break
            # apiref.apireport(file) # used to know poor documented API using introspection

            if file.MIMEType:
                typedir = file.MIMEType.replace("/", "_")
                contentDir = os.path.join(config.output_path, typedir)
            else:
                typedir = "other"
                contentDir = defaultcontentDir
            id = "%12d" % file.getId()
            filepath = os.path.join(contentDir, id + "-" + file.getName())
            # process file if its a not a well known file
            isKnown = (file.getKnown() == TskData.FileKnown.UNKNOWN)
            # process file if has MimeType or if other option is True
            saveOtherFile = (config.other | bool(file.MIMEType))
            isIncludedType = (typedir not in config.excluded_MimeTypes)
            processFile = (isKnown and saveOtherFile and isIncludedType)

            line = [typedir, file.getName(), file.getParentPath(), str(file.getId()), str(file.getMd5Hash())]

            if not processFile:
                excluded_files.write(u','.join(line) + "\n")
            else:
                try:
                    if not os.path.exists(contentDir):
                        os.mkdir(contentDir)
                    if not os.path.exists(filepath):
                        ContentUtils.writeToFile(file, File(filepath))
                    report.write(u','.join(line) + "\n")
                except:
                    excluded_files.write(u','.join(line) + "\n")
                    self.log(Level.WARNING, str(sys.exc_info()[0]) + "-" +  str(sys.exc_info()[1]) + "\n" + u','.join(line))
            progressBar.increment()

        report.close()
        excluded_files.close()

        # Add the report to the Case, so it is shown in the tree
        Case.getCurrentCase().addReport(fileName, self.moduleName, "Copy Not Known Files")

        progressBar.complete(ReportStatus.COMPLETE)

