from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- KONFIGURACJA ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'twoj_sekretny_klucz' 

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

# --- MODELE BAZY DANYCH ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    role = db.Column(db.String(20)) 

# Nowa tabela: Ulubione Kryptowaluty
class FavoriteCrypto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50)) # np. 'bitcoin', 'ethereum'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- SETUP ---
@app.route('/setup')
def setup():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            hashed_pw = generate_password_hash('admin123', method='pbkdf2:sha256')
            admin = User(username='admin', password=hashed_pw, role='admin')
            db.session.add(admin)
            
            # Dodajmy adminowi Bitcoina na start
            btc = FavoriteCrypto(symbol='bitcoin', user_id=1)
            db.session.add(btc)

            hashed_pw_user = generate_password_hash('user123', method='pbkdf2:sha256')
            student = User(username='student', password=hashed_pw_user, role='student')
            db.session.add(student)
            
            db.session.commit()
            return "Baza gotowa! Admin ma już Bitcoina w ulubionych."
        return "Baza już istnieje."

# --- WIDOKI ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return "Błędne hasło lub login", 401
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Pobieramy ulubione waluty zalogowanego użytkownika
    favorites = FavoriteCrypto.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', user=current_user, favorites=favorites)

# --- API (Backend dla Fetch) ---

@app.route('/api/add_crypto', methods=['POST'])
@login_required
def add_crypto():
    data = request.get_json()
    symbol = data.get('symbol').lower() # np. 'bitcoin'
    
    # Sprawdź czy już nie ma takiej na liście (żeby nie dublować)
    exists = FavoriteCrypto.query.filter_by(user_id=current_user.id, symbol=symbol).first()
    
    if symbol and not exists:
        new_crypto = FavoriteCrypto(symbol=symbol, user_id=current_user.id)
        db.session.add(new_crypto)
        db.session.commit()
        return jsonify({'message': 'Dodano', 'symbol': symbol})
    
    return jsonify({'message': 'Błąd lub duplikat'}), 400

@app.route('/api/delete_crypto', methods=['POST'])
@login_required
def delete_crypto():
    data = request.get_json()
    crypto_id = data.get('id')
    
    crypto = FavoriteCrypto.query.get(crypto_id)
    if crypto and crypto.user_id == current_user.id:
        db.session.delete(crypto)
        db.session.commit()
        return jsonify({'message': 'Usunięto'})
        
    return jsonify({'message': 'Błąd'}), 400

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)