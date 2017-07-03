#!/usr/bin/python
'''

June 20 2017 | 3PM
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

def sshvm(servers,packages):
    try:
        #hostname = raw_input('HostName/IP address: ')
        #username = raw_input('UserName: ')
        #password = getpass.getpass('Password: ')
        with open('servers', 'r') as myfile:
            for i in range(2):
                (username,ip)=myfile.readline().replace('\n', '').split("@")

                print username
                print ip
                s = pxssh.pxssh()
                s.login(ip,username)
        
                #s.sendline('dpkg --get-selections | grep tree')
                #s.prompt()
                #print s.before   
                 
                s.sendline('sudo apt-get install elinks')
                s.sendline(getpass.getpass('Authorize yourself: '))
                #s.sendline('Y')
                s.prompt()
                print(s.before)
                
                #s.sendline('dpkg --get-selections | grep tree')
                #s.prompt()
                #print s.before   
                   
                pack_file = open(packages, 'rU')
                for package in pack_file:
                    s.sendline('sudo apt-get install %s'%package)
                    s.sendline('Y')
                    s.prompt()
                print s.before
                
                '''
In case, We want to check whether a package is installed or not before installing :::
                s.sendline('dpkg --get-selections | grep %s'%package)
                s.prompt()
                print s.before
                match = re.search(r'\sinstall',s.before)
                if match:
                    print "Already installed\n"
                else:
                    s.sendline('sudo apt-get install %s'%package)
                    s.prompt()
                    print "%s package successfully installed"%package
             
       Or We can use :::     
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
                s.logout()
                s.close()

    except pxssh.ExceptionPxssh,e:
        print 'pxssh failed on login!'
        print str(e)
        
def main():
    if not sys.argv[1:]:
        print "Usage: [ username@serverIPaddress ] or use file to connect to multiple servers"
        sys.exit(1)
    #(username,ip) = sys.argv[1].split('@')
    #print username
    #print ip
    multiple_servers = sys.argv[1]
    packages = sys.argv[2]
    sshvm(multiple_servers,packages)

if __name__ == '__main__':
    main()
