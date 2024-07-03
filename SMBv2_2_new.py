# import pyshark for the python analysis
import pyshark
# import os for the creation of folders and files
import os
# import json for to include json into this file
import json

#Folder creation, this will also check if the same folder is already created, if created it will not create again.
#This folder will be created in the same directory that this python file will be saved
currentpath = os.getcwd()
nameofFolder = "Yadel"

if not os.path.exists(currentpath + '/' + nameofFolder):
    os.mkdir(nameofFolder)

#The first section, using the filecaputre we will import the given wireshark file from the user into our pyshark environment., we will apply smb2.cm ==8 filter to
#filter smbv2 read request and response sections.
#We will use the path that has been created above to create our file read2 pcap which will extract the filtered outputs.
print("Enter the path of the Wireshark (pcap) file you want parsed")
path = input()
d = pyshark.FileCapture(path, display_filter='smb2.cmd == 8', output_file= r'Yadel\new.pcap')
d.load_packets()

#In this section we will import the given file from the user
#We will apply the filter smb2.cm == 8 to filter the read reqeust and response sections
#We will privde additional filter mb2.flags.response == 0 to get only the request section
#We will use the user_json=true file to play with the json files
c = pyshark.FileCapture(path, display_filter='smb2.cmd == 8&&smb2.flags.response == 0', use_json=True)
for pkt in c:
#Here we will set the path where the json file will be created.
    file_path = r"Yadel\new.json"
    with open(file_path, 'w') as file:

        #Here we will apply our filters of the Read request output like the source ip address of the smbv2 session and dump them to the json file created above.
        # file.write('File Name =')
        # json.dump(pkt.smb2.olb_offset, file, indent=4)
        # file.write('\nFile Size =')
        # json.dump(pkt.data.data_len, file, indent=4)
        file.write('Source ip =')
        json.dump(pkt.ip.src, file, indent=4)
        file.write('\nSource port =')
        json.dump(pkt.tcp.srcport, file, indent=4)
        file.write('\nDestnation IP =')
        json.dump(pkt.ip.dst, file, indent=4)
        file.write('\nDestination port =')
        json.dump(pkt.tcp.dstport, file, indent=4)