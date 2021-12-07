# #######################
# # PasswordBreachCheck #
# #######################
# ------------------------------------------------------------------------------
# Author: Ruben Wylleman
# Creation: 07DEC2021
#
# Version: 1.0
# Version date: 07DEC2021
#
# Functions:
# check_arguments
# 
# Usage:
# This script allows the user to check it's passwords safely against known breach databases.
# for this first version the 'haveibeenpwnd' API is used to check the password integrity.
# 
# for current version only strings will be processed (read as one password per execution)
# File check features will be implementend in later versions.




import sys
import hashlib


# this function will check for any arguments.
def check_arguments():
    Arg_Amount = len(sys.argv)
    if Arg_Amount == 1:
        print("please enter a value")
        quit()
    else:
        return 1

# this function will hash it's input using SHA1 and return the hashed value in HEX
def hashing(string_in):
    encoded_string=string_in.encode()
    hash_obj=hashlib.sha1(encoded_string)
    hexa_value=hash_obj.hexdigest()
    return hexa_value
  

def main():
    check_arguments()
    Value_To_Hash = sys.argv[1]
    hash_Result=hashing(Value_To_Hash)
    print(hash_Result)

if __name__ == "__main__":
    main()