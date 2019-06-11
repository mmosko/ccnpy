

class PosixTime:
    """
    superclass for fields that are defined as POSIX time in msec since epoch
    """
    def __init(self, posix_time):
        self._posix_time = posix_time

    @classmethod
    def deserialize(cls, buffer):
        #TODO: finish
        return cls(0)

    def serialize(self):
        pass