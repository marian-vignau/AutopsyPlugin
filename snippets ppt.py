from org.sleuthkit.autopsy.report \
    import GeneralReportModuleAdapter

class NotKnownBackup(
    GeneralReportModuleAdapter):

    moduleName = "Copy Not Known Files"

    def getName(self):
        return self.moduleName

    def getDescription(self):
        return "Copy Not Known Files,”

    def getRelativeFilePath(self):
        return "hashes.csv"

---------------------------------------

from java.util.logging \
    import Level
from org.sleuthkit.autopsy.coreutils \
    import Logger

class NotKnownBackup(
    GeneralReportModuleAdapter):
...
    _logger = None
    def log(self, level, msg):
        if self._logger == None:
            self._logger = \
                Logger.getLogger(
                    self.moduleName)
        self._logger.logp(
            level,
            self.__class__.__name__,
            inspect.stack()[1][3], msg)

---------------------------------------
class NotKnownBackup(
    GeneralReportModuleAdapter):
...


    def generateReport(self,
                       baseReportDir,
                       progressBar):

        fileName = \
            os.path.join(baseReportDir,
            self.getRelativeFilePath())

        report = codecs.open(fileName,
                 'w', "utf8")

        print(report, baseReportDir, progressBar)


---------------------------------------


def generateReport(self,
                   baseReportDir,
                   progressBar):
    ...

    sleuthkitCase = Case.\
        getCurrentCase().\
        getSleuthkitCase()

    files = sleuthkitCase.\
        findAllFilesWhere(
        "NOT meta_type = " +
        str(TskData.
            TSK_FS_META_TYPE_ENUM.
            TSK_FS_META_TYPE_DIR.
            getValue()))

    print(files, baseReportDir, progressBar)


---------------------------------------

def generateReport(self,
                   baseReportDir,
                   progressBar):
    ...
    if not os.path.exists(
            config.output_path):
        os.mkdir(output_path)

    defaultcontentDir = \
        os.path.join(output_path,
                     "Other")

    if not os.path.exists(
            defaultcontentDir):
        os.mkdir(defaultcontentDir)

    print(files, baseReportDir, progressBar)


---------------------------------------



for idx, file in enumerate(files):
    if file.MIMEType:
        typedir = \
            file.MIMEType.\
                replace("/", "_")

        contentDir = \
            os.path.join(
                output_path,
                typedir)
    else:
        typedir = "other"
        contentDir = \
            defaultcontentDir


---------------------------------------

id = "%12d" % file.getId()

filepath = os.path.join(
            contentDir,
            id + "-" + file.getName())

isKnown = (file.getKnown() ==
           TskData.FileKnown.UNKNOWN)

line = [typedir,
        file.getName(),
        file.getParentPath(),
        str(file.getId()),
        str(file.getMd5Hash())]

---------------------------------------

if not isKnown:
    try:
        if not os.path.exists(
                contentDir):
            os.mkdir(contentDir)

        ContentUtils.writeToFile(
            file, File(filepath))

        report.write(u','.join(line)
                     + "\n")

    except:
        self.log(Level.WARNING,
            str(sys.exc_info()[0]) + "-" +
            str(sys.exc_info()[1]) + "\n" +
            u','.join(line))



---------------------------------------

class NotKnownBackup(
    GeneralReportModuleAdapter):
    ...


    def generateReport(self,
                       baseReportDir,
                       progressBar):
        ...
        report.close()
        Case.getCurrentCase().\
            addReport(
            fileName,
            self.moduleName,
            "Copy Not Known Files")

        print(files, baseReportDir, progressBar)
