from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
# Make sure NumberRange is imported here:
from wtforms import SelectField, StringField, PasswordField, SubmitField, IntegerField, DecimalField
from wtforms.validators import DataRequired, Length, EqualTo, NumberRange
from functools import wraps
from sqlalchemy import text

app = Flask(__name__)
app.config['SECRET_KEY'] = 'A_Secret_Key_Here' 
# FIX 1: Removed the invalid '?' character
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:capitanRey1080?@localhost/lego_market_database'
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True) 
    name = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

class Piece(db.Model):
    __tablename__ = 'piece'
    piece_id = db.Column(db.String(128), primary_key=True)
    name = db.Column(db.String(255), nullable=False)

class Color(db.Model):
    __tablename__ = 'color'
    color_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    is_trans = db.Column(db.Boolean, nullable=False, default=False)

class Inventory(db.Model):
    __tablename__ = 'inventory'
    inventory_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    piece_id = db.Column(db.String(128), db.ForeignKey('piece.piece_id'))
    color_id = db.Column(db.Integer, db.ForeignKey('color.color_id'))
    quantity = db.Column(db.Integer, default=0)
    price = db.Column(db.Numeric(10, 2))
    
    piece = db.relationship('Piece')
    color = db.relationship('Color')
    user = db.relationship('User') 

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Repeat Password')
    submit = SubmitField('Register')

class AddInventoryForm(FlaskForm):
    piece_id = SelectField('Piece', validators=[DataRequired()], coerce=str)
    color_id = SelectField('Color', validators=[DataRequired()], coerce=int)
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)], default=1)
    price = DecimalField('Price per Unit', validators=[DataRequired(), NumberRange(min=0.01)], places=2)
    submit = SubmitField('Add to Inventory')


class Wishlist(db.Model):
    __tablename__ = 'wishlist'
    wishlist_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    name = db.Column(db.String(100))

    user = db.relationship('User', backref=db.backref('wishlists', lazy=True))
    items = db.relationship('WishlistItem', backref='wishlist', lazy=True)

class WishlistItem(db.Model):
    __tablename__ = 'wishlist_items'
    wishlist_id = db.Column(db.Integer, db.ForeignKey('wishlist.wishlist_id'), primary_key=True)
    piece_id = db.Column(db.String(128), db.ForeignKey('piece.piece_id'), primary_key=True)
    color_id = db.Column(db.Integer, db.ForeignKey('color.color_id'), primary_key=True)
    quantity = db.Column(db.Integer, default=1)
    
    piece = db.relationship('Piece')
    color = db.relationship('Color')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    user_inventory = db.session.query(Inventory).join(Piece).join(Color).filter(
            Inventory.user_id == session['user_id'],
            Inventory.quantity > 0
        ).all()
    
    market_inventory = db.session.query(Inventory).join(Piece).join(Color).join(User).filter(
        Inventory.user_id != session['user_id'],
        Inventory.quantity > 0
    ).all()

    form = AddInventoryForm()
    pieces = Piece.query.all()
    colors = Color.query.all()
    form.piece_id.choices = [(p.piece_id, f"{p.name} ({p.piece_id})") for p in pieces]
    form.color_id.choices = [(c.color_id, c.name) for c in colors]
        
    return render_template(
        'index.html', 
        username=session['username'],
        market_inventory=market_inventory,
        user_inventory=user_inventory,
        form=form
    )

@app.route('/add_inventory', methods=['POST'])
@login_required
def add_inventory():
    form = AddInventoryForm()
    
    # CRITICAL: Populate choices BEFORE validation runs
    pieces = Piece.query.all()
    colors = Color.query.all()
    form.piece_id.choices = [(p.piece_id, f"{p.name} ({p.piece_id})") for p in pieces]
    form.color_id.choices = [(c.color_id, c.name) for c in colors]
    
    if form.validate_on_submit():
        try:
            existing_item = Inventory.query.filter_by(
                user_id=session['user_id'],
                piece_id=form.piece_id.data,
                color_id=form.color_id.data
            ).first()
            
            if existing_item:
                existing_item.quantity += form.quantity.data
                existing_item.price = form.price.data
                flash('Item quantity updated in your inventory!', 'success')
            else:
                new_item = Inventory(
                    user_id=session['user_id'],
                    piece_id=form.piece_id.data,
                    color_id=form.color_id.data,
                    quantity=form.quantity.data,
                    price=form.price.data
                )
                db.session.add(new_item)
                flash('Item added to your inventory!', 'success')
            
            db.session.commit()
            
        except Exception as e:
            db.session.rollback() 
            print(f"Database Error during commit: {e}") 
            flash(f'A database error occurred: {str(e)[:100]}', 'error')
            
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {getattr(form, field).label.text}: {error}", 'error')
        flash('Please correct the input errors above.', 'error')
    
    return redirect(url_for('index'))

@app.route('/wishlist')
@login_required
def wishlist():
    current_user_id = session['user_id']
    
    # Query for all wishlists belonging to the current user, along with their items
    user_wishlists = Wishlist.query.filter_by(user_id=current_user_id).all()
    
    return render_template(
        'wishlist.html', 
        username=session['username'],
        wishlists=user_wishlists
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(name=form.username.data).first()
        
        if user is None or user.password != form.password.data:
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))
        
        session['user_id'] = user.id
        session['username'] = user.name
        flash(f'Logged in as {user.name}!', 'success')
        return redirect(url_for('index'))
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user_exists = User.query.filter_by(name=form.username.data).first()
        if user_exists:
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))

        new_user = User(name=form.username.data, password=form.password.data)
        
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

if __name__ == '__main__':
    with app.app_context():
        app.run(debug=True)
