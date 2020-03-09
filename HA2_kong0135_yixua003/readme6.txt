First, we get the mac encoded text of:
"."
".."
...
"...................."

by this script:
#!/bin/bash
for num in {0..20}; do
line=`perl -e "print '.' x $num;"`
echo $line
curl http://192.168.6.1/mac-cookie?username=$line  >> output.txt
done

The output is stored in output.csv (trim some columns)
raw_text	encode_text
	a2f0aa1bdb0baf5eaa5c9e39af07afba4044cfe1
.	6b634e13e39916feaee94c4fee38ca0a18c11d29
..	071331394facd8ff8381f32499689576dcd10f74
...	276fa5d1211a0b36ebd8abde5e37f1a5c5c049fb
....	ddfe9624ae45433552f6b59ddc30bed56340eae6
.....	cdfe9e5ece237f76e2e81f829cad5487db512431
......	70042ea661f5d2e984e1ed2d9691eaff5ca89499
.......	e01d53fd2003ced9fd2220546097ec54b0bb274a
........	09c88f8086b6f72707be389ead4b6b16c3a437b5
.........	04dd550305dc6c97dc3a92d87cced35224b9a939
..........	75b68dbd620550d2139d4d9d2373b198424c76cf
...........	9a58115a4c59b4bb5c0df1120987b5ecf3897d23
............	2faa6a8ed6a2148ed1e6626a0edc89432458805a
.............	848e2edad12c71f563facad2650fe1b7843f1c66
..............	1518e69041f3168d4f27dda7cd892f657b34d113
...............	685753ff2b99ae2ce4f1a4a5fb5f6c38730422f6
................	04211d127dbcdf39cf33e4a9e7e5e8ea80876398
.................	ad1cce5e0188b1ff87455719dab373cf2df9f44c
..................	84d0dbad0f812d5eede30b2549b7706cda62d1ff
...................	08cff407e0187e3e0d90a85df0cf3e65069b5e0f

Let key = "". Then for input = ..................., we try all the possible character c, get sha1(input+key+c), find c such that sha1(input+c) = 08cff407e0187e3e0d90a85df0cf3e65069b5e0f, append c the key. Repeat this step and we get the secret key:
DUOgD1SlzYaUbP5zkfuT


