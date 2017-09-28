# Packet-Analyser

Implement the packet analyser to get the details of the Packet
Language: Java
Input: Path to the datafile or the file name

Steps to execute the code:

1. Extract PktAnalyser.java from Packet_Analyser.zip file
2. Open command prompt and go to the directory of PktAnalyser.java
3. Compile PktAnalyser using javac:

javac PktAnalyser.java

4. Run the file providing the path of the datafile as input in strings:

java PktAnalyser "/home/stu13/s11/dp6417/Courses/Sem3/FCN/new_icmp_packet2.bin/"

This will print the contents of the new_icmp_packet2.bin file


Provide the full path of the datafile if the datafiles are in another directory.
Example: java PktAnalyser "/home/stu13/s11/dp6417/Courses/Sem3/FCN/new_icmp_packet2.bin/"

If datafile is in the same directory as PktAnalyser.java, just provide the file_name of datafile.
Example: java PktAnalyser new_icmp_packet2.bin

