- Dependencies

-Install libCURL
-Install libXML

- Compile command

gcc -o app `xml2-config --cflags` crawler.c `xml2-config --libs` -lcurl && app
