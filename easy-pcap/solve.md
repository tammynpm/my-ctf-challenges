# The Vanishing Secret Solve

When you first click the `Get flag` button, it will show you an image saying that the flag has been removed. 
If you open the traffic capture packet, filters out the http traffic, you can find a http POST request to a weird endpoint. You will see the message sent with the request. Decode this message and go to the exact endpoint. Then with the found credentials, you can log into the `Admin Console` page. This is where the real flag has been moved to by the attacker. 

Flag: `MINUTEMAN{5u64r_5p1c3_4nd_3v3ry7h1n6_n1c3 }`
