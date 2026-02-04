from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from datetime import datetime
import uuid
import hashlib

app = Flask(__name__)
app.secret_key = 'urbanfinds-local-dev-secret-key-2026'

users_db = {}
properties_db = {}
applications_db = {}
notifications_db = {}

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_id(prefix=''):
    return f"{prefix}{uuid.uuid4().hex[:12]}"

def create_notification(recipient_id, notification_type, message):
    notification_id = generate_id('notif_')
    notifications_db[notification_id] = {
        'notification_id': notification_id,
        'recipient_id': recipient_id,
        'type': notification_type,
        'message': message,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'read': False
    }
    return notification_id

def get_user_notifications(user_id):
    return [n for n in notifications_db.values() if n['recipient_id'] == user_id]

def require_login(role=None):
    def decorator(func):
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please login to access this page', 'error')
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                flash('You do not have permission to access this page', 'error')
                return redirect(url_for('home'))
            if session.get('status') == 'disabled':
                flash('Your account has been disabled', 'error')
                session.clear()
                return redirect(url_for('login'))
            return func(*args, **kwargs)
        wrapper.__name__ = func.__name__
        return wrapper
    return decorator

def init_sample_data():
    admin_id = generate_id('user_')
    users_db[admin_id] = {
        'user_id': admin_id,
        'name': 'Admin User',
        'email': 'admin@urbanfinds.com',
        'password': hash_password('admin123'),
        'role': 'admin',
        'status': 'active'
    }
    
    owner_id = generate_id('user_')
    users_db[owner_id] = {
        'user_id': owner_id,
        'name': 'John Owner',
        'email': 'owner@example.com',
        'password': hash_password('owner123'),
        'role': 'owner',
        'status': 'active'
    }
    
    tenant_id = generate_id('user_')
    users_db[tenant_id] = {
        'user_id': tenant_id,
        'name': 'Jane Tenant',
        'email': 'tenant@example.com',
        'password': hash_password('tenant123'),
        'role': 'tenant',
        'status': 'active'
    }
    
    property_types = ['apartment', 'house', 'land', 'commercial']
    addresses = [
        'Luxury Apartment in Downtown Mumbai, Maharashtra',
        'Spacious Villa in Whitefield, Bangalore',
        '5 Acre Agricultural Land in Pune Outskirts',
        'Commercial Office Space in Cyber City, Gurgaon'
    ]
    prices = [8500000, 12000000, 3500000, 15000000]
    descriptions = [
        '3 BHK luxury apartment with modern amenities, swimming pool, gym, and 24/7 security.',
        'Beautiful 4 BHK independent house with garden, parking for 3 cars, and solar panels.',
        'Prime agricultural land with water connection, perfect for farming or investment.',
        'Grade A office space with modern infrastructure, ample parking, and metro connectivity.'
    ]
    images = [
        'https://images.unsplash.com/photo-1545324418-cc1a3fa10c00?w=800&h=600&fit=crop',
        'https://images.unsplash.com/photo-1568605114967-8130f3a36994?w=800&h=600&fit=crop',
        'https://images.unsplash.com/photo-1500382017468-9049fed747ef?w=800&h=600&fit=crop',
        'https://images.unsplash.com/photo-1486406146926-c627a92ad1ab?w=800&h=600&fit=crop'
    ]
    
    for i in range(4):
        prop_id = generate_id('prop_')
        properties_db[prop_id] = {
            'property_id': prop_id,
            'type': property_types[i],
            'address': addresses[i],
            'price': prices[i],
            'description': descriptions[i],
            'owner_id': owner_id,
            'images': [images[i]],
            'status': 'active'
        }

init_sample_data()

@app.route('/')
def home():
    stats = {
        'total_properties': len([p for p in properties_db.values() if p['status'] == 'active']),
        'total_users': len(users_db),
        'total_applications': len(applications_db)
    }
    return render_template('home.html', stats=stats)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
        if not all([name, email, password, role]):
            flash('All fields are required', 'error')
            return redirect(url_for('register'))
        
        if role not in ['tenant', 'owner']:
            flash('Invalid role selected', 'error')
            return redirect(url_for('register'))
        
        if any(u['email'] == email for u in users_db.values()):
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        user_id = generate_id('user_')
        users_db[user_id] = {
            'user_id': user_id,
            'name': name,
            'email': email,
            'password': hash_password(password),
            'role': role,
            'status': 'active'
        }
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = next((u for u in users_db.values() if u['email'] == email), None)
        
        if not user or user['password'] != hash_password(password):
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))
        
        if user['role'] == 'admin':
            flash('Admin users must use the admin login page', 'error')
            return redirect(url_for('admin_login'))
        
        if user['status'] == 'disabled':
            flash('Your account has been disabled', 'error')
            return redirect(url_for('login'))
        
        session['user_id'] = user['user_id']
        session['name'] = user['name']
        session['email'] = user['email']
        session['role'] = user['role']
        session['status'] = user['status']
        
        flash(f'Welcome back, {user["name"]}!', 'success')
        
        if user['role'] == 'owner':
            return redirect(url_for('dashboard_owner'))
        else:
            return redirect(url_for('dashboard_tenant'))
    
    return render_template('login.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = next((u for u in users_db.values() if u['email'] == email and u['role'] == 'admin'), None)
        
        if not user or user['password'] != hash_password(password):
            flash('Invalid admin credentials', 'error')
            return redirect(url_for('admin_login'))
        
        session['user_id'] = user['user_id']
        session['name'] = user['name']
        session['email'] = user['email']
        session['role'] = user['role']
        session['status'] = user['status']
        
        flash(f'Welcome, {user["name"]}!', 'success')
        return redirect(url_for('dashboard_admin'))
    
    return render_template('admin_login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

@app.route('/properties')
def properties():
    active_properties = [p for p in properties_db.values() if p['status'] == 'active']
    return render_template('properties.html', properties=active_properties)

@app.route('/properties/<property_id>')
def property_detail(property_id):
    property_data = properties_db.get(property_id)
    
    if not property_data:
        return render_template('error_404.html'), 404
    
    has_applied = False
    if session.get('user_id'):
        has_applied = any(
            a['property_id'] == property_id and a['seeker_id'] == session['user_id']
            for a in applications_db.values()
        )
    
    return render_template('property_detail.html', property=property_data, has_applied=has_applied)

@app.route('/properties/add', methods=['GET', 'POST'])
@require_login('owner')
def add_property():
    if request.method == 'POST':
        property_type = request.form.get('type')
        address = request.form.get('address')
        price = request.form.get('price')
        description = request.form.get('description')
        image_url = request.form.get('image_url', 'https://images.unsplash.com/photo-1560518883-ce09059eeffa?w=800&h=600&fit=crop')
        
        if not all([property_type, address, price]):
            flash('Please fill all required fields', 'error')
            return redirect(url_for('add_property'))
        
        property_id = generate_id('prop_')
        properties_db[property_id] = {
            'property_id': property_id,
            'type': property_type,
            'address': address,
            'price': float(price),
            'description': description,
            'owner_id': session['user_id'],
            'images': [image_url],
            'status': 'active'
        }
        
        flash('Property added successfully!', 'success')
        return redirect(url_for('dashboard_owner'))
    
    return render_template('add_property.html')

@app.route('/applications/submit', methods=['POST'])
@require_login('tenant')
def submit_application():
    property_id = request.form.get('property_id')
    
    property_data = properties_db.get(property_id)
    if not property_data:
        flash('Property not found', 'error')
        return redirect(url_for('properties'))
    
    existing = any(
        a['property_id'] == property_id and a['seeker_id'] == session['user_id']
        for a in applications_db.values()
    )
    
    if existing:
        flash('You have already applied for this property', 'warning')
        return redirect(url_for('property_detail', property_id=property_id))
    
    app_id = generate_id('app_')
    applications_db[app_id] = {
        'application_id': app_id,
        'property_id': property_id,
        'seeker_id': session['user_id'],
        'status': 'pending',
        'request_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    create_notification(
        property_data['owner_id'],
        'application_submitted',
        f"New application received for your property at {property_data['address']}"
    )
    
    flash('Application submitted successfully!', 'success')
    return redirect(url_for('dashboard_tenant'))

@app.route('/applications')
@require_login('owner')
def applications():
    owner_properties = [p['property_id'] for p in properties_db.values() if p['owner_id'] == session['user_id']]
    
    owner_applications = []
    for app in applications_db.values():
        if app['property_id'] in owner_properties:
            property_data = properties_db[app['property_id']]
            seeker_data = users_db[app['seeker_id']]
            
            owner_applications.append({
                **app,
                'property_address': property_data['address'],
                'property_type': property_data['type'],
                'property_price': property_data['price'],
                'seeker_name': seeker_data['name'],
                'seeker_email': seeker_data['email']
            })
    
    return render_template('applications.html', applications=owner_applications)

@app.route('/api/applications/<app_id>/status', methods=['POST'])
@require_login('owner')
def update_application_status(app_id):
    app_data = applications_db.get(app_id)
    
    if not app_data:
        return jsonify({'error': 'Application not found'}), 404
    
    property_data = properties_db.get(app_data['property_id'])
    if property_data['owner_id'] != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    new_status = request.json.get('status')
    if new_status not in ['approved', 'rejected']:
        return jsonify({'error': 'Invalid status'}), 400
    
    applications_db[app_id]['status'] = new_status
    
    create_notification(
        app_data['seeker_id'],
        f'application_{new_status}',
        f"Your application for {property_data['address']} has been {new_status}"
    )
    
    return jsonify({'success': True, 'status': new_status})

@app.route('/dashboard/owner')
@require_login('owner')
def dashboard_owner():
    owner_properties = [p for p in properties_db.values() if p['owner_id'] == session['user_id']]
    
    property_ids = [p['property_id'] for p in owner_properties]
    owner_applications = []
    
    for app in applications_db.values():
        if app['property_id'] in property_ids:
            property_data = properties_db[app['property_id']]
            seeker_data = users_db[app['seeker_id']]
            
            owner_applications.append({
                **app,
                'property_address': property_data['address'],
                'property_type': property_data['type'],
                'property_price': property_data['price'],
                'property_image': property_data['images'][0] if property_data['images'] else None,
                'seeker_name': seeker_data['name'],
                'seeker_email': seeker_data['email']
            })
    
    for prop in owner_properties:
        prop['application_count'] = len([a for a in applications_db.values() if a['property_id'] == prop['property_id']])
    
    stats = {
        'total_properties': len(owner_properties),
        'active_properties': len([p for p in owner_properties if p['status'] == 'active']),
        'total_applications': len(owner_applications),
        'pending_applications': len([a for a in owner_applications if a['status'] == 'pending'])
    }
    
    return render_template('dashboard_owner.html', 
                         properties=owner_properties, 
                         applications=owner_applications,
                         stats=stats)

@app.route('/dashboard/tenant')
@require_login('tenant')
def dashboard_tenant():
    tenant_applications = []
    
    for app in applications_db.values():
        if app['seeker_id'] == session['user_id']:
            property_data = properties_db.get(app['property_id'])
            if property_data:
                tenant_applications.append({
                    **app,
                    'property_address': property_data['address'],
                    'property_type': property_data['type'],
                    'property_price': property_data['price'],
                    'property_image': property_data['images'][0] if property_data['images'] else None
                })
    
    stats = {
        'total_applications': len(tenant_applications),
        'pending_applications': len([a for a in tenant_applications if a['status'] == 'pending']),
        'approved_applications': len([a for a in tenant_applications if a['status'] == 'approved']),
        'rejected_applications': len([a for a in tenant_applications if a['status'] == 'rejected'])
    }
    
    return render_template('dashboard_tenant.html', 
                         applications=tenant_applications,
                         stats=stats)

@app.route('/dashboard/admin')
@require_login('admin')
def dashboard_admin():
    stats = {
        'total_users': len(users_db),
        'active_users': len([u for u in users_db.values() if u['status'] == 'active']),
        'total_properties': len(properties_db),
        'active_properties': len([p for p in properties_db.values() if p['status'] == 'active']),
        'total_applications': len(applications_db),
        'pending_applications': len([a for a in applications_db.values() if a['status'] == 'pending'])
    }
    
    recent_users = sorted(users_db.values(), key=lambda x: x['user_id'], reverse=True)[:5]
    recent_properties = sorted(properties_db.values(), key=lambda x: x['property_id'], reverse=True)[:5]
    
    return render_template('dashboard_admin.html', 
                         stats=stats,
                         recent_users=recent_users,
                         recent_properties=recent_properties)

@app.route('/admin/users')
@require_login('admin')
def admin_users():
    all_users = [u for u in users_db.values() if u['role'] != 'admin']
    return render_template('admin_users.html', users=all_users)

@app.route('/admin/properties')
@require_login('admin')
def admin_properties():
    all_properties = list(properties_db.values())
    return render_template('admin_properties.html', properties=all_properties)

@app.route('/admin/applications')
@require_login('admin')
def admin_applications():
    all_applications = []
    
    for app in applications_db.values():
        property_data = properties_db.get(app['property_id'])
        seeker_data = users_db.get(app['seeker_id'])
        
        if property_data and seeker_data:
            all_applications.append({
                **app,
                'property_address': property_data['address'],
                'property_type': property_data['type'],
                'seeker_name': seeker_data['name']
            })
    
    return render_template('admin_applications.html', applications=all_applications)

@app.route('/api/users/<user_id>/status', methods=['POST'])
@require_login('admin')
def toggle_user_status(user_id):
    user = users_db.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    new_status = request.json.get('status')
    if new_status not in ['active', 'disabled']:
        return jsonify({'error': 'Invalid status'}), 400
    
    users_db[user_id]['status'] = new_status
    
    create_notification(
        user_id,
        'account_status_changed',
        f"Your account has been {new_status} by an administrator"
    )
    
    return jsonify({'success': True, 'status': new_status})

@app.route('/api/properties/<property_id>', methods=['DELETE'])
@require_login('owner')
def delete_property(property_id):
    property_data = properties_db.get(property_id)
    
    if not property_data:
        return jsonify({'error': 'Property not found'}), 404
    
    if property_data['owner_id'] != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    del properties_db[property_id]
    
    return jsonify({'success': True})

@app.route('/api/admin/properties/<property_id>/remove', methods=['POST'])
@require_login('admin')
def remove_property(property_id):
    if property_id in properties_db:
        properties_db[property_id]['status'] = 'removed'
        return jsonify({'success': True})
    
    return jsonify({'error': 'Property not found'}), 404

@app.route('/notifications')
@require_login()
def notifications():
    user_notifications = get_user_notifications(session['user_id'])
    user_notifications.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return render_template('notifications.html', notifications=user_notifications)

@app.route('/api/notifications/unread-count')
@require_login()
def unread_notifications_count():
    user_notifications = get_user_notifications(session['user_id'])
    unread_count = len([n for n in user_notifications if not n['read']])
    
    return jsonify({'count': unread_count})

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'mode': 'local',
        'database': 'python_dictionaries',
        'users': len(users_db),
        'properties': len(properties_db),
        'applications': len(applications_db),
        'notifications': len(notifications_db)
    })

@app.errorhandler(404)
def not_found(e):
    return render_template('error_404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error_500.html'), 500

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🏢 UrbanFinds - Local Development Server")
    print("="*60)
    print("\n📝 Sample Credentials:")
    print("   Admin:  admin@urbanfinds.com / admin123")
    print("   Owner:  owner@example.com / owner123")
    print("   Tenant: tenant@example.com / tenant123")
    print("\n🌐 Server running at: http://localhost:5000")
    print("="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
