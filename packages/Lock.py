# @file     Lock.py
# @author   Sebastien LEGRAND
# @date     2017-01-26
#
# @brief    Class to implement a lock mechanism with a file
# @history
#           2017-01-26 - 1.0.0 - SLE
#           Initial Version
# @notes
#           If the mode is set to not blocking, trying to acquire a file that is currently locked
#           will generate an IOError exception


# imports
#----------
import fcntl

# class
#----------
class Lock:
    def __init__(self, lockFile):
        self.fh = open(lockFile, "w")

    # acquire the lock
    def acquire(self, blocking = True):
        ops = fcntl.LOCK_EX
        if not blocking:
            ops |= fcntl.LOCK_NB

        fcntl.flock(self.fh, ops)

    # release the lock
    def release(self):
        fcntl.flock(self.fh, fcntl.LOCK_UN)

    # close the file when the object gets destroyed
    def __del__(self):
        self.fh.close()
