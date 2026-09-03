# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Custom Conditions
#
#   A class that may contain additional conditions to check for a given user.
#   This way we can first check if the user is a member of a given
#   group (for example).
#   Custom conditions should be added under the below class as functions.
#   Any function is acceptable except those that start and end with two
#   underscores ("__" in each side. If name like this is set anyways, 
#   the function will be ignored from the checks).
#   The function must return True when the checked condition is passed. If
#   not, the condition result will be False!
#   If there is more than one conditions, all the conditions must return True
#   in order for the final check to pass
#
# Author:
#   Roy Rahamim / @0xRoyR
#
class Conditions:
    def __init__(self, username):
        conditions = [getattr(self.__class__, c) for c in self.__class__.__dict__.keys() if not (c.startswith('__') and c.endswith('__'))]
        self.verified = all([c(username) for c in conditions])
    
    @staticmethod
    def example1(username):
        # Place here the code for your first condition
        return True
    
    @staticmethod
    def example2(username):
        # Place here the code for your second condition
        return True
