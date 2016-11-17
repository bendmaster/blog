import os
import re
import random
import hashlib
import hmac
from string import letters
import webapp2
import jinja2
import time
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'supersecretsecret'


def render_str(template, **params):
    """Uses the jinja2 framework to render HTML
    templates using defined parameters"""

    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    """Uses HMAC to return a hashed value
    in the form of "value|hashed value"""

    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    """Using the output from make_secure_val method
    in the form of "val|hashed val" this method
    checks to see if, when re-run through make_secure_val
    the val matches the hash and if so, return the val"""

    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def render_post(response, post):
    """This method writes a bolded subject with a break
    followed by the content"""
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


def make_salt(length=5):
    """This method returns a random string
    of 5 letters to be used as a salt"""
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    """This method returns a salted password in the form
    of "salt,salted password"""
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    """Returns boolean value using the make_pw_hash method
    to see if, when re-run, the password hash, h, is valid"""
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    """Creates the ancestor element for the users database,
    allowing for the potential of user-grouping"""
    return db.Key.from_path('users', group)


def delete_entity(name):
    name.key.delete()


def blog_key(name='default'):
    """Creates an ancestor element for Blogs entity"""
    return db.Key.from_path('blogs', name)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    """checks to see if username is provided and
    has valid characters and is between 3 and 20 char length"""
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    """checks to see if password is provided and
    meets the 3-20 char length requirement"""
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    """If an email is provided, checks the validity
    of the email"""
    return not email or EMAIL_RE.match(email)


class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        """Returns user info from the Users entity"""
        return cls.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        """Looks up user by name and returns user info"""
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        """Creates a new user object but does not store it in the database"""
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    created_by = db.StringProperty()
    likes = db.StringProperty()
    # parent_post = db.StringProperty()

    def render(self):
        """Converts lines into breaks for easy readability"""
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class Comment(db.Model):
    orig_post = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    posted_by = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        """Converts lines into breaks for easier readability"""
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", p=self)


class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        """Writes the values provided"""
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """Returns the user value into the defined template"""
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        """Render the template using defined parameters"""
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """Creates a cookie using the make_secure_val method"""
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """Reads the user's [name] cookie and uses the
        check_secure_val method to verify the validity of the cookie"""
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login_set_cookie(self, user):
        """Uses the set_secure_cookie method to set the user_id cookie"""
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        """sets user_id to nothing, effectively deleting the cookie
        and logging user out"""
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        """Reads user_id cookie and, if valid, sets the user as that user_id"""
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class BlogFront(BlogHandler):

    def get(self):
        """Renders blog frontpage with blogs in order of
        creation time, newest-oldest"""
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
        user_id = self.read_secure_cookie("user_id")  # this is new
        # user_id is new
        self.render('front.html', posts=posts, user_id=user_id)


class PostPage(BlogHandler):

    def get(self, post_id):
        """Renders a page showing the recently created blog post, its likes or unlikes,
        an ability to comment or a 404 page if the post does not exist"""
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        user_id = self.read_secure_cookie('user_id')

        if post.likes and user_id in post.likes:
             likeOption = 'unlike'
        else:
             likeOption = 'like'

        if post.likes:
            likeCount = len(post.likes)
        else:
            likeCount = 0

        comments = []

        #comments = db.GqlQuery("SELECT * FROM Comment WHERE orig_post = %s" % post)

        # for comment in comments:
        #     print(comments)

        if not post:
            self.error(404)
            return

        post._render_text = post.content.replace('\n', '<br>')
        self.render("permalink.html", post=post, comments=comments, likeoption=likeOption,
                    likes=likeCount)

        # if not post:
        #     self.error(404)
        #     return
        # post._render_text = post.content.replace('\n', '<br>')

        # self.render("post.html", post=post, likeText=likeText,
        #     totalLikes=totalLikes, uid=uid, comments=comments)

    def post(self, post_id):
        if not self.user:
            return self.redirect('/')

        subject = self.request.get('subject')
        content = self.request.get('content')

        user_id = self.read_secure_cookie('user_id')

        if subject and content:
            post = Post(parent=blog_key(), subject=subject,
                        content=content, created_by=user_id)
            post.put()
            return self.redirect('/post/%s' % post_id)
        else:
            error = "subject and content, please!"
            self.render(
                "post.html", subject=subject, content=content, error=error)


class NewPost(BlogHandler):

    def get(self):
        """allows logged in user to create post"""
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        """If logged in, allows user to post blog content
        and throws error if all required fields are not filled in"""
        if not self.user:
            self.redirect('/')
            return

        subject = self.request.get('subject')
        content = self.request.get('content')
        user = self.request.cookies.get('user_id')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject,
                     content=content, created_by=user)
            p.put()
            self.redirect('/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render(
                "newpost.html", subject=subject, content=content, error=error)


class Signup(BlogHandler):

    def get(self):
        """renders the signup page"""
        self.render("signup-form.html")

    def post(self):
        """checks if a valid username, password, and email are entered
        and throws errors if not"""
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        """creates a method to be inherited"""
        raise NotImplementedError


class Register(Signup):

    def done(self):
        """makes sure the user doesn't already exist"""
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login_set_cookie(u)
            self.redirect('/')


class Login(BlogHandler):

    def get(self):
        """renders the login form page"""
        self.render('login-form.html')

    def post(self):
        """posts the username and password and sets the
        respective cookies then redirects to blogfront,
        otherwise throws errors"""
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login_set_cookie(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):

    def get(self):
        """uses the logout method to effectively log user out"""
        self.logout()
        self.redirect('/')


class LikeAction(BlogHandler):
    """This class allows users to anonymously increase or
        decrease the like count of a post"""
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        user_id = self.read_secure_cookie('user_id')

        if not post:
            self.error(404)
            return

        if post.created_by != user_id:

            if post.likes and user_id in post.likes:
                post.likes.remove(user_id)
            else:
                post.likes.append(user_id)

            post.put()

            self.redirect('/post/%s' % str(post.key().id()))

        else:
            error = 'Liking your own posts is tacky. Denied.'
            self.redirect('/post/%s' % str(post.key().id()), error = error)


class DeletePage(BlogHandler):

    """This class allows user to delete their
     own posts and prevents others from doing so"""

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.redirect("/")
            return

        user_id = self.read_secure_cookie('user_id')

        if post.user_id != uid:
            error = 'This is not your post. Denied.'
        else:
            error = ''
            db.delete(key)

        self.render("delete.html", error=error)


class EditPage(BlogHandler):

    """This class allows users to edit their posts and prevents
    others from tampering with them"""

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        user_id = self.read_secure_cookie('user_id')

        if post.created_by != user_id:
            error = 'You are not permitted to edit this post'
        else:
            error = ''

        self.render("edit.html", post=post, error=error, uid=uid)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        user_id = self.read_secure_cookie('user_id')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content and post.created_by == user_id:
            post.subject = subject
            post.content = content
            post.put()
            # if post.parent_post:
            #     redirect_id = post.parent_post
            # else:
            #     redirect_id = post.key().id()
            # self.redirect('/post/%s' % str(redirect_id))
            self.redirect('/post/%s' % str(post_id))
        else:
            error = "subject and content, please!"
            self.render("edit.html", post=post, error=error)


class Welcome(BlogHandler):

    def get(self):
        """Checks to see if user is valid, otherwise redirects to signup"""
        if self.user:
            self.render('welcome.html', username=self.user.name)

        else:
            self.redirect('/signup')


class ViewPosts(BlogHandler):

    def get(self, posts):
        pass

app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/([0-9]+)', PostPage),
                               ('/newpost', NewPost),
                               ('/edit/([0-9]+)', EditPage),
                               ('/delete/([0-9]+)', DeletePage),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ],
                              debug=True)
