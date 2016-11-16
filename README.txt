-----------
What is it?
-----------

The Back End Web Dev Blog is a simple website that allows users to submit blog posts after creating an account.


-----------
Contents
-----------
This directory contains 2 important files and 2 sub-folders:

1. blog.py
	- This file contains all of the methods and handlers used to render the webpages and provide functionality, 
          including logging in/out and creating new posts
	- This file also contains the security mechanisms for protecting user accounts
2. app.yaml
	- This file contains the configurations used by the Google Cloud to run the website

3./static
	- This folder contains all of the CSS used by the website

4./templates
	- This folder contains the pre-made HTML rendered by the website

-----------
How to Run
-----------
1. Locally:
	- Make sure you have the Google Cloud SDK with Python downloaded: https://cloud.google.com/sdk/docs/
	- Open a Bash shell and navigate to the folder contain the app.yaml file and enter the command "dev_appserver.py ."
2. On the internet:
	- Visit https://blog-149105.appspot.com


-----------
How to Modify
-----------

Modifications to the functionality of the website can be performed on the blog.py file.

Modifications to the appearance of the website can be performed on the HTML files within the templates folder.

-----------
Troubleshooting
-----------
Please ensure you have downloaded the the Google Cloud SDK and installed per the instructions.


-----------
Licensing
-----------
The author does not claim any right to this project. Feel free to use in whatever capacity you feel appropriate.

-----------
Credit
-----------
The login and signup pages were based on the template made available by Aigars Silkalns from his website http://codepen.io/colorlib/
Credit for their appearance should be given to him.