from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from datetime import datetime
import uuid
import hashlib
import boto3
from botocore.exceptions import ClientError

app = Flask(__name__)
app.secret_key = 'urbanfinds-aws-production-secret-key-2026'

AWS_REGION = 'us-east-1'

dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
sns_client = boto3.client('sns', region_name=AWS_REGION)

USERS_TABLE = 'UrbanFinds_Users'
PROPERTIES_TABLE = 'UrbanFinds_Properties'
APPLICATIONS_TABLE = 'UrbanFinds_Applications'
NOTIFICATIONS_TABLE = 'UrbanFinds_Notifications'

SNS_TOPIC_ARN = 'arn:aws:sns:ap-south-1:YOUR_ACCOUNT_ID:UrbanFinds-Notifications'

users_table = dynamodb.Table(USERS_TABLE)
properties_table = dynamodb.Table(PROPERTIES_TABLE)
applications_table = dynamodb.Table(APPLICATIONS_TABLE)
notifications_table = dynamodb.Table(NOTIFICATIONS_TABLE)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_id(prefix=''):
    return f"{prefix}{uuid.uuid4().hex[:12]}"

def send_sns_notification(email, subject, message):
    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message,
            MessageAttributes={
                'email': {
                    'DataType': 'String',
                    'StringValue': email
                }
            }
        )
        return True
    except ClientError as e:
        print(f"SNS Error: {e}")
        return False

def create_notification(recipient_id, notification_type, message):
    notification_id = generate_id('notif_')
    
    try:
        notifications_table.put_item(
            Item={
                'notification_id': notification_id,
                'recipient_id': recipient_id,
                'type': notification_type,
                'message': message,
                'timestamp': datetime.now().isoformat(),
                'read': False
            }
        )
        
        user_response = users_table.get_item(Key={'user_id': recipient_id})
        if 'Item' in user_response:
            user_email = user_response['Item']['email']
            send_sns_notification(user_email, f'UrbanFinds - {notification_type}', message)
        
        return notification_id
    except ClientError as e:
        print(f"DynamoDB Error: {e}")
        return None

def get_user_by_email(email):
    try:
        response = users_table.scan(
            FilterExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        if response['Items']:
            return response['Items'][0]
        return None
    except ClientError as e:
        print(f"DynamoDB Error: {e}")
        return None

def get_user_notifications(user_id):
    try:
        response = notifications_table.scan(
            FilterExpression='recipient_id = :user_id',
            ExpressionAttributeValues={':user_id': user_id}
        )
        return response['Items']
    except ClientError as e:
        print(f"DynamoDB Error: {e}")
        return []

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

@app.route('/')
def home():
    try:
        properties_response = properties_table.scan(
            FilterExpression='#status = :status',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':status': 'active'}
        )
        users_response = users_table.scan()
        applications_response = applications_table.scan()
        
        stats = {
            'total_properties': len(properties_response['Items']),
            'total_users': len(users_response['Items']),
            'total_applications': len(applications_response['Items'])
        }
    except ClientError:
        stats = {'total_properties': 0, 'total_users': 0, 'total_applications': 0}
    
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
        
        if get_user_by_email(email):
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        user_id = generate_id('user_')
        try:
            users_table.put_item(
                Item={
                    'user_id': user_id,
                    'name': name,
                    'email': email,
                    'password': hash_password(password),
                    'role': role,
                    'status': 'active'
                }
            )
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except ClientError as e:
            flash('Registration failed. Please try again.', 'error')
            print(f"DynamoDB Error: {e}")
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = get_user_by_email(email)
        
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
        
        user = get_user_by_email(email)
        
        if not user or user['role'] != 'admin' or user['password'] != hash_password(password):
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
    try:
        response = properties_table.scan(
            FilterExpression='#status = :status',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':status': 'active'}
        )
        active_properties = response['Items']
    except ClientError:
        active_properties = []
    
    return render_template('properties.html', properties=active_properties)

@app.route('/properties/<property_id>')
def property_detail(property_id):
    try:
        response = properties_table.get_item(Key={'property_id': property_id})
        
        if 'Item' not in response:
            return render_template('error_404.html'), 404
        
        property_data = response['Item']
        
        has_applied = False
        if session.get('user_id'):
            app_response = applications_table.scan(
                FilterExpression='property_id = :pid AND seeker_id = :sid',
                ExpressionAttributeValues={
                    ':pid': property_id,
                    ':sid': session['user_id']
                }
            )
            has_applied = len(app_response['Items']) > 0
        
        return render_template('property_detail.html', property=property_data, has_applied=has_applied)
    except ClientError:
        return render_template('error_404.html'), 404

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
        try:
            properties_table.put_item(
                Item={
                    'property_id': property_id,
                    'type': property_type,
                    'address': address,
                    'price': float(price),
                    'description': description,
                    'owner_id': session['user_id'],
                    'images': [image_url],
                    'status': 'active'
                }
            )
            
            flash('Property added successfully!', 'success')
            return redirect(url_for('dashboard_owner'))
        except ClientError as e:
            flash('Failed to add property. Please try again.', 'error')
            print(f"DynamoDB Error: {e}")
            return redirect(url_for('add_property'))
    
    return render_template('add_property.html')

@app.route('/applications/submit', methods=['POST'])
@require_login('tenant')
def submit_application():
    property_id = request.form.get('property_id')
    
    try:
        prop_response = properties_table.get_item(Key={'property_id': property_id})
        if 'Item' not in prop_response:
            flash('Property not found', 'error')
            return redirect(url_for('properties'))
        
        property_data = prop_response['Item']
        
        app_response = applications_table.scan(
            FilterExpression='property_id = :pid AND seeker_id = :sid',
            ExpressionAttributeValues={
                ':pid': property_id,
                ':sid': session['user_id']
            }
        )
        
        if app_response['Items']:
            flash('You have already applied for this property', 'warning')
            return redirect(url_for('property_detail', property_id=property_id))
        
        app_id = generate_id('app_')
        applications_table.put_item(
            Item={
                'application_id': app_id,
                'property_id': property_id,
                'seeker_id': session['user_id'],
                'status': 'pending',
                'request_date': datetime.now().isoformat()
            }
        )
        
        create_notification(
            property_data['owner_id'],
            'application_submitted',
            f"New application received for your property at {property_data['address']}"
        )
        
        flash('Application submitted successfully!', 'success')
        return redirect(url_for('dashboard_tenant'))
    except ClientError as e:
        flash('Failed to submit application. Please try again.', 'error')
        print(f"DynamoDB Error: {e}")
        return redirect(url_for('properties'))

@app.route('/applications')
@require_login('owner')
def applications():
    try:
        props_response = properties_table.scan(
            FilterExpression='owner_id = :oid',
            ExpressionAttributeValues={':oid': session['user_id']}
        )
        owner_property_ids = [p['property_id'] for p in props_response['Items']]
        
        owner_applications = []
        for prop_id in owner_property_ids:
            apps_response = applications_table.scan(
                FilterExpression='property_id = :pid',
                ExpressionAttributeValues={':pid': prop_id}
            )
            
            for app in apps_response['Items']:
                property_data = properties_table.get_item(Key={'property_id': app['property_id']})['Item']
                seeker_data = users_table.get_item(Key={'user_id': app['seeker_id']})['Item']
                
                owner_applications.append({
                    **app,
                    'property_address': property_data['address'],
                    'property_type': property_data['type'],
                    'property_price': property_data['price'],
                    'seeker_name': seeker_data['name'],
                    'seeker_email': seeker_data['email'],
                    'request_date': datetime.fromisoformat(app['request_date']).strftime('%Y-%m-%d %H:%M')
                })
        
        return render_template('applications.html', applications=owner_applications)
    except ClientError:
        return render_template('applications.html', applications=[])

@app.route('/api/applications/<app_id>/status', methods=['POST'])
@require_login('owner')
def update_application_status(app_id):
    try:
        app_response = applications_table.get_item(Key={'application_id': app_id})
        if 'Item' not in app_response:
            return jsonify({'error': 'Application not found'}), 404
        
        app_data = app_response['Item']
        
        property_response = properties_table.get_item(Key={'property_id': app_data['property_id']})
        property_data = property_response['Item']
        
        if property_data['owner_id'] != session['user_id']:
            return jsonify({'error': 'Unauthorized'}), 403
        
        new_status = request.json.get('status')
        if new_status not in ['approved', 'rejected']:
            return jsonify({'error': 'Invalid status'}), 400
        
        applications_table.update_item(
            Key={'application_id': app_id},
            UpdateExpression='SET #status = :status',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':status': new_status}
        )
        
        create_notification(
            app_data['seeker_id'],
            f'application_{new_status}',
            f"Your application for {property_data['address']} has been {new_status}"
        )
        
        return jsonify({'success': True, 'status': new_status})
    except ClientError as e:
        print(f"DynamoDB Error: {e}")
        return jsonify({'error': 'Failed to update application'}), 500

@app.route('/dashboard/owner')
@require_login('owner')
def dashboard_owner():
    try:
        props_response = properties_table.scan(
            FilterExpression='owner_id = :oid',
            ExpressionAttributeValues={':oid': session['user_id']}
        )
        owner_properties = props_response['Items']
        
        property_ids = [p['property_id'] for p in owner_properties]
        owner_applications = []
        
        for prop_id in property_ids:
            apps_response = applications_table.scan(
                FilterExpression='property_id = :pid',
                ExpressionAttributeValues={':pid': prop_id}
            )
            
            for app in apps_response['Items']:
                property_data = properties_table.get_item(Key={'property_id': app['property_id']})['Item']
                seeker_data = users_table.get_item(Key={'user_id': app['seeker_id']})['Item']
                
                owner_applications.append({
                    **app,
                    'property_address': property_data['address'],
                    'property_type': property_data['type'],
                    'property_price': property_data['price'],
                    'property_image': property_data['images'][0] if property_data.get('images') else None,
                    'seeker_name': seeker_data['name'],
                    'seeker_email': seeker_data['email'],
                    'request_date': datetime.fromisoformat(app['request_date']).strftime('%Y-%m-%d %H:%M')
                })
        
        for prop in owner_properties:
            apps_count = applications_table.scan(
                FilterExpression='property_id = :pid',
                ExpressionAttributeValues={':pid': prop['property_id']}
            )
            prop['application_count'] = len(apps_count['Items'])
        
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
    except ClientError:
        return render_template('dashboard_owner.html', properties=[], applications=[], stats={})

@app.route('/dashboard/tenant')
@require_login('tenant')
def dashboard_tenant():
    try:
        apps_response = applications_table.scan(
            FilterExpression='seeker_id = :sid',
            ExpressionAttributeValues={':sid': session['user_id']}
        )
        
        tenant_applications = []
        for app in apps_response['Items']:
            property_response = properties_table.get_item(Key={'property_id': app['property_id']})
            if 'Item' in property_response:
                property_data = property_response['Item']
                tenant_applications.append({
                    **app,
                    'property_address': property_data['address'],
                    'property_type': property_data['type'],
                    'property_price': property_data['price'],
                    'property_image': property_data['images'][0] if property_data.get('images') else None,
                    'request_date': datetime.fromisoformat(app['request_date']).strftime('%Y-%m-%d %H:%M')
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
    except ClientError:
        return render_template('dashboard_tenant.html', applications=[], stats={})

@app.route('/dashboard/admin')
@require_login('admin')
def dashboard_admin():
    try:
        users_response = users_table.scan()
        properties_response = properties_table.scan()
        applications_response = applications_table.scan()
        
        all_users = users_response['Items']
        all_properties = properties_response['Items']
        all_applications = applications_response['Items']
        
        stats = {
            'total_users': len(all_users),
            'active_users': len([u for u in all_users if u['status'] == 'active']),
            'total_properties': len(all_properties),
            'active_properties': len([p for p in all_properties if p['status'] == 'active']),
            'total_applications': len(all_applications),
            'pending_applications': len([a for a in all_applications if a['status'] == 'pending'])
        }
        
        recent_users = sorted(all_users, key=lambda x: x['user_id'], reverse=True)[:5]
        recent_properties = sorted(all_properties, key=lambda x: x['property_id'], reverse=True)[:5]
        
        return render_template('dashboard_admin.html', 
                             stats=stats,
                             recent_users=recent_users,
                             recent_properties=recent_properties)
    except ClientError:
        return render_template('dashboard_admin.html', stats={}, recent_users=[], recent_properties=[])

@app.route('/admin/users')
@require_login('admin')
def admin_users():
    try:
        response = users_table.scan()
        all_users = [u for u in response['Items'] if u['role'] != 'admin']
        return render_template('admin_users.html', users=all_users)
    except ClientError:
        return render_template('admin_users.html', users=[])

@app.route('/admin/properties')
@require_login('admin')
def admin_properties():
    try:
        response = properties_table.scan()
        return render_template('admin_properties.html', properties=response['Items'])
    except ClientError:
        return render_template('admin_properties.html', properties=[])

@app.route('/admin/applications')
@require_login('admin')
def admin_applications():
    try:
        apps_response = applications_table.scan()
        
        all_applications = []
        for app in apps_response['Items']:
            property_data = properties_table.get_item(Key={'property_id': app['property_id']})['Item']
            seeker_data = users_table.get_item(Key={'user_id': app['seeker_id']})['Item']
            
            all_applications.append({
                **app,
                'property_address': property_data['address'],
                'property_type': property_data['type'],
                'seeker_name': seeker_data['name'],
                'request_date': datetime.fromisoformat(app['request_date']).strftime('%Y-%m-%d %H:%M')
            })
        
        return render_template('admin_applications.html', applications=all_applications)
    except ClientError:
        return render_template('admin_applications.html', applications=[])

@app.route('/api/users/<user_id>/status', methods=['POST'])
@require_login('admin')
def toggle_user_status(user_id):
    try:
        new_status = request.json.get('status')
        if new_status not in ['active', 'disabled']:
            return jsonify({'error': 'Invalid status'}), 400
        
        users_table.update_item(
            Key={'user_id': user_id},
            UpdateExpression='SET #status = :status',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':status': new_status}
        )
        
        create_notification(
            user_id,
            'account_status_changed',
            f"Your account has been {new_status} by an administrator"
        )
        
        return jsonify({'success': True, 'status': new_status})
    except ClientError as e:
        print(f"DynamoDB Error: {e}")
        return jsonify({'error': 'Failed to update user status'}), 500

@app.route('/api/properties/<property_id>', methods=['DELETE'])
@require_login('owner')
def delete_property(property_id):
    try:
        property_response = properties_table.get_item(Key={'property_id': property_id})
        if 'Item' not in property_response:
            return jsonify({'error': 'Property not found'}), 404
        
        if property_response['Item']['owner_id'] != session['user_id']:
            return jsonify({'error': 'Unauthorized'}), 403
        
        properties_table.delete_item(Key={'property_id': property_id})
        
        return jsonify({'success': True})
    except ClientError as e:
        print(f"DynamoDB Error: {e}")
        return jsonify({'error': 'Failed to delete property'}), 500

@app.route('/api/admin/properties/<property_id>/remove', methods=['POST'])
@require_login('admin')
def remove_property(property_id):
    try:
        properties_table.update_item(
            Key={'property_id': property_id},
            UpdateExpression='SET #status = :status',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':status': 'removed'}
        )
        
        return jsonify({'success': True})
    except ClientError as e:
        print(f"DynamoDB Error: {e}")
        return jsonify({'error': 'Failed to remove property'}), 500

@app.route('/notifications')
@require_login()
def notifications():
    user_notifications = get_user_notifications(session['user_id'])
    user_notifications.sort(key=lambda x: x['timestamp'], reverse=True)
    
    for notif in user_notifications:
        notif['timestamp'] = datetime.fromisoformat(notif['timestamp']).strftime('%Y-%m-%d %H:%M')
    
    return render_template('notifications.html', notifications=user_notifications)

@app.route('/api/notifications/unread-count')
@require_login()
def unread_notifications_count():
    user_notifications = get_user_notifications(session['user_id'])
    unread_count = len([n for n in user_notifications if not n.get('read', False)])
    
    return jsonify({'count': unread_count})

@app.route('/health')
def health():
    try:
        users_table.scan(Limit=1)
        db_status = 'connected'
    except:
        db_status = 'disconnected'
    
    return jsonify({
        'status': 'healthy',
        'mode': 'aws',
        'database': 'dynamodb',
        'database_status': db_status,
        'region': AWS_REGION,
        'sns_enabled': True
    })

@app.errorhandler(404)
def not_found(e):
    return render_template('error_404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error_500.html'), 500

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🏢 UrbanFinds - AWS Cloud Server")
    print("="*60)
    print(f"\n☁️  AWS Region: {AWS_REGION}")
    print("📊 Database: DynamoDB")
    print("🔔 Notifications: SNS")
    print("🔐 Authentication: IAM Roles")
    print("\n🌐 Server running at: http://0.0.0.0:5000")
    print("="*60 + "\n")
    
    app.run(debug=False, host='0.0.0.0', port=5000)
