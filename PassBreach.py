# #######################
# # PasswordBreachCheck #
# #######################
# ------------------------------------------------------------------------------
# Author: Ruben Wylleman
# Creation: 07DEC2021

# Version: 1.0
# Version date: 07DEC2021

# Functions:
# Main() - main program
# check_arguments() - check if arguments are present.
# hashing("str") - converts string to hash1 value.
# Check_Hash_to_Hidb("hashed_str") - searches the HIBP database for a match
# help() - Help function

# Usage:
# This script allows the user to check it's passwords safely against known breach databases.
# for this first version the 'haveibeenpwnd' API is used to check the password integrity.

# for current version only strings will be processed (read as one password per execution)
# File check features will be implementend in later versions.

# use the option -h for help and usage


import sys
import hashlib
import requests
import getopt

# this function will check for any arguments.
def check_arguments():
    Arg_Amount = len(sys.argv) #check the total number of arguments
    if Arg_Amount == 1: ## if the amount is only 1, there are no additional arguments added, so ask for a value and quit program.
        help()
        quit()
    else:
        return 1

# this function will hash it's input using SHA1 and return the hashed value in HEX
def hashing(string_in):
    encoded_string=string_in.encode() # FOr hashing, the string value needs to be converted to binary
    hash_obj=hashlib.sha1(encoded_string) # Now we hash the encoded string en return the result to variable.
    hexa_value=hash_obj.hexdigest() # Now let's convert the hashed value to HEX.
    return hexa_value
  
# main function
def main(argv):
    inputfile = ''
    # added switch functionality -h and -i. 
    try: # try chacking for options and arguments if fail goto help and exit program.
      opts, args = getopt.getopt(argv,"hi:",["ifile="])
    except getopt.GetoptError:
      help()
      sys.exit(2)
    for opt, arg in opts:
        if opt == '-h': # if -h selected, open help menu.
            help()
            sys.exit()
        elif opt in ("-i","--inputfile"): # if -i selected load argument in inputfile var for later handling
            inputfile = arg
            inputfile = "work in progress"
            print(inputfile)
            sys.exit()
    check_arguments()# check if arguments are entered
    Value_To_Hash = argv[0] # assign entered value to variable
    hash_Result=hashing(Value_To_Hash) # create a hash1 value from the entered argument. and enter result in variable.
    check_hash_to_HIDB(hash_Result) # check the hash1 value to the databases OF HIBP


def check_hash_to_HIDB(hash):
    # HIBP API only needs the first 5 Hex characters of the Hash1 password.
    # The API returns a block data with approx 500 lines of hashes beginning with the same 5 chars.
    # Attention! the returned results are the complete hash without the first 5 chars ! 
    HIDB_Response = requests.get('https://api.pwnedpasswords.com/range/' + hash[:5]) 
    HIDB_Hitlist = HIDB_Response._content.decode("utf-8") # To work the returned list, we convert it to utf8 format
    # In order to check the lists for our hash, we will need to iterate the list.
    # we prepare a 'match' variable in order to escape if we have a match.
    # The returned list values are separated by a return carriage \r\n, we'll split the values based on this sequence.
    match=0
    for line in HIDB_Hitlist.split('\r\n'):
        if line.split(':')[0] == hash[5:].upper(): # match our hash, without the first 5 chars, to the list
            print("oops, we have a match")
            match=1
            exit

    if match == 0:
        print("you are safe!")
    

    
def help():
    multilinehelp = """\nUsage:\n\n
    This script allows the user to check it's passwords safely against known breach databases.
    for this first version the 'haveibeenpwnd' API is used to check the password integrity.
    for current version only strings will be processed (read as one password per execution)
    File check features will be implementend in later versions.
    Enter the PassBreach command followed by the password you like to check.
    \n\nExample:
    \n\"PassBreach password123\"\n\n
    PassBreach -h for help\n"""
    print(multilinehelp)   



if __name__ == "__main__":
    main(sys.argv[1:])