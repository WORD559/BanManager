#Dummy error for when Authentication fails
class AuthenticationError(Exception):
    pass

#Dummy error for when no FileKey is available
class FileKeyError(Exception):
    pass

class DatabaseConnectError(Exception):
    pass

class ForeignKeyError(Exception):
    pass

class RecordExistsError(Exception):
    pass

class RankError(Exception):
    pass

class PhotoError(Exception):
    pass
