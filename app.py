from flask import Flask, request, session, jsonify, render_template, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_migrate import Migrate
from flask_jwt_extended import set_access_cookies
from flask_mail import Mail, Message
from datetime import timedelta
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import os
import requests
import stripe
import logging

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///boat_slips.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key_here'
app.config['UPLOAD_FOLDER'] = 'assets/photos/'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False  # Set to True for HTTPS
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token_cookie'  # Name of the access token cookie
app.config['JWT_REFRESH_COOKIE_NAME'] = 'refresh_token_cookie'  # Name of the refresh token cookie
app.config['JWT_COOKIE_CSRF_PROTECT'] = True  # Set to True for CSRF protection
app.secret_key = 'your_secret_key_here'
app.config['MAIL_SERVER'] = 'ixplorer.com@gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ixplorer.com@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'kolw rrzk bvto kdfc'  # Replace with your email password or app password
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'
logging.basicConfig(level=logging.DEBUG)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate with app and db

# Create upload folder
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

load_dotenv()

mail = Mail(app)
jwt = JWTManager(app)
saved_listings_data = []

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class BoatSlip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(120), nullable=False)
    latitude = db.Column(db.Float, nullable=False)  # Add latitude
    longitude = db.Column(db.Float, nullable=False)  # Add longitude
    price = db.Column(db.Float, nullable=False)
    image_filename = db.Column(db.String(120))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner = db.relationship('User', backref=db.backref('boat_slips', lazy=True))
    email = db.Column(db.String(120), nullable=False)
    hoa_fees = db.Column(db.Float, nullable=False)
    property_taxes = db.Column(db.Float, nullable=False)
    length = db.Column(db.Float, nullable=False)
    width = db.Column(db.Float, nullable=False)

    # Add this method to serialize BoatSlip objects
    def to_dict(self):
        return { 
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'location': self.location,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'price': self.price,
            'image_filename': self.image_filename,
            'owner_id': self.owner_id
        }    
            
class RentSlip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    price_year = db.Column(db.Float, nullable=False)
    price_month = db.Column(db.Float, nullable=True)
    marina = db.Column(db.String(100), nullable=False)
    marina_address = db.Column(db.String(200), nullable=False)
    length = db.Column(db.Float, nullable=False)
    width = db.Column(db.Float, nullable=False)
    slip_number = db.Column(db.String(50), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(2), nullable=False)
    electricity = db.Column(db.String(3), nullable=False)
    water = db.Column(db.String(3), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
        
stripe.api_key = "sk_test_51Qdz4k2NotfB72cN5AmJWcjumCbiqSCuQB7Bvwun2UqiJ4wWVSc6EvXnGvxfgJCtbOjuNvbNS3hZK89Ahomiudk100cFRKmtj3"        

# Routes
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200
    
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)  # Clear session
    return jsonify({"msg": "Logged out"}), 200

@app.route('/register', methods=['POST'])
def register():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 400

    user = User(username=username, email=email)
    user.set_password(password)

    try:
        db.session.add(user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()  # Prevent database lock by rolling back if there's an issue
        return jsonify({'error': str(e)}), 500
    finally:
        db.session.close()  # Ensure session is closed

    return redirect(url_for('dashboard'))
    
@app.route('/register_form', methods=['GET'])
def register_form():
    return render_template('register.html')

from flask import redirect, url_for

@app.route('/login', methods=['POST'])
def login():
    session.permanent = True
    data = request.get_json()  # Or request.form if not JSON
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401

    # Set user_id in the session
    session['user_id'] = user.id
    print(f"Session set: {session['user_id']}")  # Debugging

    # Create a JWT token
    access_token = create_access_token(identity=user.id)
    response = jsonify({'msg': 'Login successful', 'access_token': access_token})

    # Set the JWT in a cookie
    set_access_cookies(response, access_token)
    return response, 200
    
@app.route('/login_form', methods=['GET', 'POST'])
def login_form():
    if request.method == 'GET':
        # Render the login form for GET requests
        return render_template('login.html')

    elif request.method == 'POST':
        session.permanent = True

        # Handle both JSON and form data for flexibility
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        email = data.get('email')
        password = data.get('password')

        # Authenticate the user
        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            return jsonify({'error': 'Invalid credentials'}), 401

        # Create a JWT token (convert user.id to a string)
        access_token = create_access_token(identity=str(user.id))

        # Create a response and set the JWT as a cookie
        response = redirect(url_for('dashboard'))  # Redirect to /dashboard
        set_access_cookies(response, access_token)  # Store JWT in the cookie

        return response

@app.route('/dashboard', methods=['GET'])
@jwt_required(optional=True)
def dashboard():
    current_user_id = get_jwt_identity()
    print(f"Current User ID: {current_user_id}")  # Debugging

    if not current_user_id:
        print("Redirecting to /login_form: User not authenticated")
        return redirect(url_for('login_form'))

    # Fetch the user
    user = db.session.get(User, current_user_id)
    if not user:
        print("Error: User not found in the database.")
        return redirect(url_for('login_form'))

    print(f"User found: {user.username}")
    return render_template('dashboard.html', user=user, boat_slips=user.boat_slips)
    
@app.route('/boat_slips', methods=['GET', 'POST'])
def handle_boat_slip():
    if request.method == 'GET':
        return render_template('create_boat_slip.html')

    # POST logic
    current_user_id = get_jwt_identity()
    data = request.form
    file = request.files['image']

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    boat_slip = BoatSlip(
        title=data.get('title'),
        description=data.get('description'),
        location=data.get('location'),
        latitude=float(data.get('latitude')),  # New field
        longitude=float(data.get('longitude')),  # New field
        price=float(data.get('price')),
        image_filename=filename,
        owner_id=current_user_id
    )

    db.session.add(boat_slip)
    db.session.commit()
    
    return redirect(url_for('dashboard'))
    return jsonify({'message': 'Boat slip created successfully'}), 201

@app.route('/listing/<int:listing_id>', methods=['GET'])
def listing_detail(listing_id):
    # Log the listing ID received in the route
    logging.debug(f"Fetching listing with ID: {listing_id}")
    
    # Fetch the listing from the database using the ID
    listing = BoatSlip.query.get_or_404(listing_id)
    if listing:
        logging.debug(f"Found listing: {listing.to_dict()}")
    else:
        logging.warning(f"No listing found for ID: {listing_id}")
    
    # Render a template for the listing page
    return render_template('listing_detail.html', listing=listing)
    
@app.route('/rental_listing/<int:listing_id>', methods=['GET'])
def rental_listing_detail(listing_id):
    # Log the listing ID received in the route
    logging.debug(f"Fetching rental listing with ID: {listing_id}")
    
    # Fetch the listing from the rent_slip table using the ID
    listing = RentSlip.query.get_or_404(listing_id)
    if listing:
        logging.debug(f"Found rental listing: {listing}")
    else:
        logging.warning(f"No rental listing found for ID: {listing_id}")
    
    # Render a template for the rental listing page
    return render_template('rental_listing_detail.html', listing=listing)
    
@app.route('/rental_listing', methods=['GET'])
def rental_listing():
    return render_template('rental_listing.html')
    
@app.route('/marina_list', methods=['GET'])
def marina_list():
    return render_template('marina_list.html')    
    
@app.route('/explore_rental_listings', methods=['GET'])
def explore_rental_listings():
    # Fetch all rental listings from the RentSlip table
    rental_listings = RentSlip.query.all()

    # Pass the listings to the template
    return render_template('explore_rental_listings.html', rental_listings=rental_listings)
    
@app.route('/manage_listings', methods=['GET'])
@jwt_required()
def manage_listings():
    # Get the user ID from session or JWT
    user_id = session.get('user_id') or get_jwt_identity()

    if not user_id:
        return "Unauthorized: No user ID found in session or JWT", 401

    # Debugging
    print(f"Current user ID: {user_id}, Type: {type(user_id)}")

    # Cast user_id to integer
    user_id = int(user_id)

    # Fetch rental listings from RentSlip table
    rental_listings = RentSlip.query.filter_by(owner_id=user_id).all()

    # Debug fetched rental listings
    print(f"Fetched rental listings: {rental_listings}")

    # Fetch sale listings from BoatSlip table
    sale_listings = BoatSlip.query.filter_by(owner_id=user_id).all()

    # Debug fetched sale listings
    print(f"Fetched sale listings: {sale_listings}")

    # Render the template with both rental and sale listings
    return render_template(
        'manage_listings.html',
        rental_listings=rental_listings,
        sale_listings=sale_listings,
    )
                
@app.route('/saved_listings', methods=['GET', 'POST', 'DELETE'])
@jwt_required(optional=True)  # Optional: Require login for saving listings
def saved_listings():
    global saved_listings_data
    logging.debug("Received a request to /saved_listings with method: %s", request.method)

    if request.method == 'GET':
        # Render saved listings
        return render_template('saved_listings.html', listings=saved_listings_data)

    data = request.get_json()
    listing_id = data.get('listing_id')

    if request.method == 'POST':
        # Check if listing ID is provided
        if not listing_id:
            return jsonify({'error': 'Listing ID is required.'}), 400

        # Check if the listing is already saved
        if any(listing['id'] == listing_id for listing in saved_listings_data):
            return jsonify({'message': 'Listing is already saved.'}), 200

        # Add the listing to the saved listings
        saved_listings_data.append({
            'id': listing_id,
            'title': data.get('title'),
            'location': data.get('location'),
            'price': data.get('price'),
            'description': data.get('description'),
            'image_filename': data.get('image_filename')
        })
        return jsonify({'message': 'Listing saved successfully.'}), 200

    if request.method == 'DELETE':
        # Remove the listing from the saved listings
        saved_listings_data = [listing for listing in saved_listings_data if listing['id'] != listing_id]
        return jsonify({'message': 'Listing unsaved successfully.'}), 200

    return jsonify({'error': 'Invalid request.'}), 400
                
@app.route('/payment_page')
def payment_page():
    return render_template('payment_page.html')    
 
@app.route('/listing_confirmation')
def listing_confirmation():
    return render_template('listing_confirmation.html')       
    
@app.route('/create-subscription', methods=['POST'])
@jwt_required()  # Ensure the user is authenticated
def create_subscription():
    try:
        # Extract payment data
        data = request.json
        payment_method_id = data.get('paymentMethodId')
        listing_data = data.get('listing')

        # Ensure payment method ID is provided
        if not payment_method_id:
            return jsonify({'error': 'Missing payment method ID'}), 400

        # Get the authenticated user's ID
        user_id = get_jwt_identity()
        if not user_id:
            return jsonify({'error': 'User not authenticated'}), 401

        # Process the payment with Stripe
        payment_intent = stripe.PaymentIntent.create(
            amount=1000,  # Amount in cents ($10.00)
            currency='usd',
            payment_method=payment_method_id,
            confirm=True,
        )

        # If payment succeeded, save the listing to the database
        if payment_intent['status'] == 'succeeded':
            if listing_data:
                new_listing = Listing(
                    user_id=user_id,
                    title=listing_data['title'],
                    location=listing_data['location'],
                    price=listing_data['price'],
                    description=listing_data['description'],
                    marina_name=listing_data['marina_name'],
                )
                db.session.add(new_listing)
                db.session.commit()

            return jsonify({'success': True}), 200
        else:
            return jsonify({'error': 'Payment failed'}), 400

    except stripe.error.CardError as e:
        # Handle card errors
        return jsonify({'error': str(e.user_message)}), 402

    except stripe.error.StripeError as e:
        # Handle other Stripe errors
        return jsonify({'error': 'Payment processing error. Please try again later.'}), 500

    except Exception as e:
        # Handle unexpected errors
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500
                    
@app.route('/contact_us')
def contact_us():
    return render_template('contact_us.html')
    
@app.route('/boat_slips_map')
def boat_slips_map():
    return render_template('boat_slips_map.html')
    
@app.route('/rental_listings_map')
def rental_listings_map():
    return render_template('rental_listings_map.html')    
    
@app.route('/confirmation')
def confirmation():
    return render_template('confirmation.html') 
    
@app.route('/terms_conditions')
def terms_conditions():
    return render_template('terms_&_conditions.html') 
    
@app.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy_policy.html')          

@app.route('/listings', methods=['GET'])
def listings():
    boat_slips = BoatSlip.query.all()
    serialized_slips = [slip.to_dict() for slip in boat_slips]
    return render_template('listings.html', boat_slips=serialized_slips)

@app.route('/boat_slips_page', methods=['GET'])
def boat_slips_page():
    north = request.args.get('north', type=float)
    south = request.args.get('south', type=float)
    east = request.args.get('east', type=float)
    west = request.args.get('west', type=float)

    if all([north, south, east, west]):
        boat_slips = BoatSlip.query.filter(
            (BoatSlip.latitude <= north) &
            (BoatSlip.latitude >= south) &
            (BoatSlip.longitude <= east) &
            (BoatSlip.longitude >= west)
        ).all()
    else:
        boat_slips = BoatSlip.query.all()

    # Serialize BoatSlip objects
    serialized_slips = [slip.to_dict() for slip in boat_slips]

    return render_template('boat_slips.html', boat_slips=serialized_slips)

@app.route('/assets/photos/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/map', methods=['GET'])
def interactive_map():
    api_key = "YOUR_GOOGLE_API_KEY"
    return render_template('map.html', api_key=api_key)

@app.route('/marinas', methods=['GET'])
def search_marinas():
    query = request.args.get('query')
    if not query:
        return jsonify({'error': 'Query parameter is required'}), 400

    api_key = "YOUR_GOOGLE_API_KEY"
    url = f"https://maps.googleapis.com/maps/api/place/textsearch/json?query={query}+marina&key={api_key}"
    response = requests.get(url)

    if response.status_code == 200:
        marinas = response.json().get('results', [])
        return render_template('marinas.html', marinas=marinas)
    else:
        return jsonify({'error': 'Failed to fetch marinas'}), 500
        
@app.route('/create-payment-intent', methods=['POST'])
def create_payment_intent():
    try:
        # Extract data sent from the frontend
        data = request.get_json()
        payment_method_id = data.get('paymentMethodId')

        # Create a PaymentIntent
        payment_intent = stripe.PaymentIntent.create(
            amount=1000,  # Amount in cents ($10.00)
            currency='usd',
            payment_method=payment_method_id,
            confirm=True,  # Automatically confirm the payment
        )

        return jsonify({'success': True})  # Respond to frontend with success
    except Exception as e:
        return jsonify({'error': str(e)}), 400  # Respond with error message

if __name__ == '__main__':
    app.run(port=5000, debug=True)
        
@app.route('/save-listing', methods=['POST'])
@jwt_required()
def save_listing():
    """
    Save the listing to the database after payment confirmation.
    """
    current_user = get_jwt_identity()
    if not current_user:
        return jsonify({"error": "User not authenticated"}), 401

    data = request.get_json()
    required_fields = ['slipName', 'location', 'price', 'width', 'length', 'taxes', 'hoaFees', 'description', 'contactInfo']
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields."}), 400

    try:
        # Save the listing to the database
        new_listing = BoatSlip(
            title=data['slipName'],
            location=data['location'],
            price=data['price'],
            width=data['width'],
            length=data['length'],
            annual_taxes=data['taxes'],
            annual_hoa_fees=data['hoaFees'],
            description=data['description'],
            contact_info=data['contactInfo'],
            owner_id=current_user
        )
        db.session.add(new_listing)
        db.session.commit()
        return jsonify({"message": "Listing created successfully.", "listing_id": new_listing.id}), 201
    except Exception as e:
        return jsonify({"error": f"Failed to save listing: {str(e)}"}), 500

@app.route('/api/boat_slips', methods=['GET'])
def get_boat_slips():
    slips = BoatSlip.query.all()
    return jsonify([{
        "title": slip.title,
        "description": slip.description,
        "lat": slip.latitude,  # Ensure these match your database columns
        "lng": slip.longitude
    } for slip in slips])
    
@app.route('/api/rent_slips', methods=['GET'])
def get_rent_slips():
    rent_slips = RentSlip.query.all()
    listings = [{
        "id": slip.id,
        "marina": slip.marina,
        "city": slip.city,
        "state": slip.state,
        "price_year": slip.price_year,
        "latitude": slip.latitude,  # Ensure these fields exist in your database
        "longitude": slip.longitude
    } for slip in rent_slips]
    return jsonify(listings)
    
@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    message = data.get('message')

    if not name or not email or not message:
        return jsonify({'error': 'All fields are required.'}), 400

    try:
        msg = Message(
            subject=f"New Message from {name}",
            sender=email,
            recipients=["ixplorer.com@gmail.com"],  # Email where you want to receive the messages
            body=f"Name: {name}\nEmail: {email}\n\nMessage:\n{message}"
        )
        mail.send(msg)
        return jsonify({'success': 'Message sent successfully.'}), 200
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': 'Failed to send message.'}), 500
        
@app.route('/update-price', methods=['POST'])
def update_price():
    data = request.json  # Get JSON data from the request
    listing_id = data.get('id')  # Extract the listing ID
    new_price = data.get('price')  # Extract the new price

    # Validate data
    if not listing_id or not isinstance(new_price, (int, float)):
        return jsonify({"error": "Invalid data"}), 400

    # Update the price in the database
    try:
        # Connect to your database
        connection = sqlite3.connect('boat_slips.db')  # Replace with your actual DB path
        cursor = connection.cursor()
        
        # Execute the SQL update
        cursor.execute("UPDATE rent_slip SET price_year = ? WHERE id = ?", (new_price, listing_id))
        
        # Check if the update was successful
        if cursor.rowcount == 0:
            return jsonify({"error": "No matching record found"}), 404
        
        # Commit changes and close connection
        connection.commit()
        connection.close()
        
        return jsonify({"message": "Price updated successfully"}), 200
    except Exception as e:
        # Handle database errors
        return jsonify({"error": f"Database error: {str(e)}"}), 500
                
@app.route("/")
def home():
    return render_template("index.html")        

# Initialize database
with app.app_context():
    db.create_all()

@app.after_request
def add_cache_control(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

if __name__ == '__main__':
    app.run(debug=True)

