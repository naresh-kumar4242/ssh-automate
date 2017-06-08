#!/usr/bin/python
'''

24 Feb 2017 | 3PM
My first official project ::: To automate the ssh into a remote server using python
This is my first little project in Python :)
It automates the following steps:

    - SSH into it (Ubuntu VM) with normal user(in my case with user naresh)
      We will be doing passwordless login to ubuntu VM.We generated SSH keys on our client & uploaded rsa_public key
      on server.We will authenticate once with simple ssh.
    
    - Install following packages
    - sudo apt-get install tree
    - sudo apt-get install cowsay   
    - prints the output of cowsay command
    
    - Add a user mayank | Give it some password
    - login with user mayank
    - Make dir testdir & touch a file testfile in mayank's home
    - log-out mayank 
    - Finally, power-off the system

-Dr z0x 

'''

import sys
from pexpect import pxssh
import getpass
import re

def sshvm(username,ip,packages):

    try:

        s = pxssh.pxssh()
        #hostname = raw_input('HostName/IP address: ')
        #username = raw_input('UserName: ')
        #password = getpass.getpass('Password: ')
        s.login(ip,username)
        
        #s.sendline('dpkg --get-selections | grep tree')
        #s.prompt()
        #print s.before   
         
        s.sendline('sudo apt-get install elinks')
        s.sendline(getpass.getpass('Authorize yourself: '))
        s.sendline('Y')
        s.prompt()
        s.prompt()
        s.prompt()
        print(s.before)
    
        pack_file = open(packages, 'rU')
        for package in pack_file:
            s.sendline('sudo apt-get install %s'%package)
            #s.sendline('Y')
            s.prompt()
            print s.before
            '''
            s.sendline('dpkg --get-selections | grep %s'%package)
            s.prompt()
            print s.before
            match = re.search(r'\sinstall',s.before)
            if match:
                print "Already installed\n"
               else:
                s.sendline('sudo apt-get install %s'%package)
                #s.sendline(getpass.getpass('Authorize yourself: '))
                s.prompt()
                print "%s package successfully installed"%package
            '''
        #s.logout()
        #sys.exit(0)
        '''
        if 'install' in s.before:
            print "Already installed\n"
        else:
            s.sendline('sudo apt-get install tree')
            s.sendline(password)
            s.prompt()
            print "tree package successfully installed"
        
        s.sendline('sudo apt-get install cowsay')
        s.sendline(password)
        print "cowsay package successfully installed"
        s.prompt()
        s.sendline('cowsay Mayank says DevOps is amazing! ')
        s.prompt()
        print s.before
        '''
        s.sendline('sudo useradd -m mayank')
        #s.sendline(password)
        s.prompt()
        print "User mayank created "
        
        s.sendline('sudo passwd mayank')
        s.sendline(getpass.getpass('Enter password for new user: ')) 
        s.sendline(getpass.getpass('Enter password again: ')) 
        s.prompt()
    
        s.sendline('su -l mayank')
        print "\nLogging in with our new user mayank "
        s.sendline(getpass.getpass('\nTo login, Enter password for user mayank: '))
        s.prompt()
        

        s.sendline('mkdir testdir ; touch testfile')
        s.prompt()
        
        s.sendline('ls -l')
        s.prompt()
        print s.before

        print 'All tasks executed successfully'
        
        s.sendline('logout')
        
        s.sendline('sudo poweroff')
        s.sendline(password)
        s.logout()

    except pxssh.ExceptionPxssh,e:
        print 'pxssh failed on login!'
        print str(e)


def main():
    
    if not sys.argv[1:]:
        print "Usage: [ username@serverIPaddress ]"
        sys.exit(1)
    (username,ip) = sys.argv[1].split('@')
    #print username
    #print ip
    packages = sys.argv[2]
    sshvm(username,ip,packages)

if __name__ == '__main__':
    main()

X

