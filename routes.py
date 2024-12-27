from flask import render_template,redirect,url_for,flash, request, jsonify
from flask_login import login_user, logout_user, current_user, login_required
from models import User
from models import (
    User, Footwear, ActivewearTops, Bottoms, Outerwear, RecoveryAndWellness,
    FootwearSubCategory, ActivewearSubCategory, BottomsSubCategory,
    OuterwearSubCategory, RecoverySubCategory, Accessories, Swimwear,
    CompressionWear, SpecialtySportswear, ProtectiveGear,
    AccessoriesSubCategory, SwimwearSubCategory, CompressionSubCategory,
    SpecialtySportswearSubCategory, ProtectiveGearSubCategory, Cart, Invoice, Report, Promotion, ReturnRequest
)
from functools import wraps  
import csv
import requests
from io import StringIO
import jwt
from datetime import datetime, timedelta
from sqlalchemy import func
from werkzeug.utils import secure_filename
import uuid
from PIL import Image
import os



def create_token(user_id,app):
    payload = {
        'sub': user_id,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(minutes=15) 
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def extract_auth_token(authenticated_request):
    auth_header = authenticated_request.headers.get('Authorization')
    if auth_header:
        return auth_header.split(" ")[1]
    else:
        return None


def decode_token(token, app):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def sanitize_input(value):
    """Sanitize input to prevent SQL injection"""
    if isinstance(value, str):
        # Remove any SQL command keywords
        sql_keywords = re.compile(
            r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE|FROM|OR|AND)\b',
            re.IGNORECASE
        )
        return sql_keywords.sub('', value)
    return value


class SecureFileUpload:
    def __init__(self):
        self.ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'csv'}
        self.MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB limit
        self.UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
        self.IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
        
        # Create upload folder if it doesn't exist
        os.makedirs(self.UPLOAD_FOLDER, exist_ok=True)
        
        # Setup logging
        logging.basicConfig(filename='file_upload.log', level=logging.INFO)
        
    def allowed_file(self, filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in self.ALLOWED_EXTENSIONS
    
    def get_safe_filename(self, filename):
        """Generate a safe filename with timestamp and hash"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename_hash = hashlib.md5(filename.encode()).hexdigest()[:10]
        ext = filename.rsplit('.', 1)[1].lower()
        return f"{timestamp}_{filename_hash}.{ext}"
    
    def validate_file_type(self, file):
        """Enhanced validation against file type spoofing"""
        try:
            # Read file header
            file_head = file.read(2048)
            file.seek(0)
            
            # Get MIME type from content
            mime = magic.from_buffer(file_head, mime=True)
            
            # Get file extension from filename
            filename = secure_filename(file.filename)
            ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
            
            # Map of allowed MIME types to their valid extensions
            allowed_types = {
                'image/jpeg': {'jpg', 'jpeg'},
                'image/png': {'png'},
                'image/gif': {'gif'},
                'text/csv': {'csv'}
            }
            
            # Check if MIME type is allowed
            if mime not in allowed_types:
                logging.warning(f"Invalid MIME type detected: {mime}")
                return False
                
            # Check if extension matches the MIME type
            if ext not in allowed_types[mime]:
                logging.warning(f"Extension mismatch: {ext} does not match {mime}")
                return False
                
            # For images, perform additional validation
            if mime.startswith('image/'):
                try:
                    with Image.open(file) as img:
                        # Verify it's actually an image
                        img.verify()
                        # Try to load the image
                        img.load()
                        # Check if image format matches claimed format
                        if img.format.lower() != ext.lower() and \
                           (ext != 'jpg' or img.format.lower() != 'jpeg'):
                            logging.warning(f"Image format mismatch: {img.format} vs {ext}")
                            return False
                    file.seek(0)
                except Exception as e:
                    logging.error(f"Image validation failed: {str(e)}")
                    return False
                    
            return True
            
        except Exception as e:
            logging.error(f"File type validation error: {str(e)}")
            return False

    def validate_image(self, file):
        """Validate and sanitize image file"""
        try:
            with Image.open(file) as img:
                # Verify it's a valid image
                img.verify()
                
                # Check image dimensions
                if img.size[0] > 4000 or img.size[1] > 4000:
                    return False
                
                return True
        except Exception as e:
            logging.error(f"Image validation error: {str(e)}")
            return False
        finally:
            file.seek(0)
    
    def sanitize_image(self, file_path):
        """Sanitize image by removing metadata and resizing if necessary"""
        try:
            with Image.open(file_path) as img:
                # Create a new image without metadata
                cleaned_img = Image.new(img.mode, img.size)
                cleaned_img.putdata(list(img.getdata()))
                
                # Optimize and save
                cleaned_img.save(file_path, optimize=True, quality=85)
                
                return True
        except Exception as e:
            logging.error(f"Image sanitization error: {str(e)}")
            return False

    def validate_saved_file(self, file_path):
        """Validate saved file before final acceptance"""
        try:
            # Check actual file on disk
            mime = magic.from_file(file_path, mime=True)
            
            # Only allow image types
            allowed_mimes = {'image/jpeg', 'image/png', 'image/gif'}
            
            if mime not in allowed_mimes:
                logging.warning(f"Saved file has invalid MIME type: {mime}")
                return False
            
            return True
            
        except Exception as e:
            logging.error(f"Saved file validation error: {str(e)}")
            return False

    def save_file(self, file, category=None):
        """Enhanced file saving with additional security checks"""
        try:
            if not file:
                return None, "No file provided"
            
            # Check file size first
            file.seek(0, os.SEEK_END)
            size = file.tell()
            file.seek(0)
            
            if size > self.MAX_FILE_SIZE:
                return None, "File size exceeds maximum limit"
            
            # Basic filename validation
            filename = secure_filename(file.filename)
            if not self.allowed_file(filename):
                return None, "File type not allowed"
            
            # Enhanced type validation
            if not self.validate_file_type(file):
                return None, "Invalid or potentially malicious file type detected"
            
            # Generate safe filename
            safe_filename = self.get_safe_filename(filename)
            
            # Determine upload path
            upload_path = self.UPLOAD_FOLDER
            if category:
                upload_path = os.path.join(upload_path, secure_filename(category))
                os.makedirs(upload_path, exist_ok=True)
            
            file_path = os.path.join(upload_path, safe_filename)
            
            # Additional validation for images
            if filename.rsplit('.', 1)[1].lower() in self.IMAGE_EXTENSIONS:
                if not self.validate_image(file):
                    return None, "Invalid image file"
                
                # Create temporary file first
                temp_path = file_path + '.tmp'
                file.save(temp_path)
                
                # Final validation on saved file
                if not self.validate_saved_file(temp_path):
                    os.remove(temp_path)
                    return None, "Final security validation failed"
                
                # Sanitize image
                if not self.sanitize_image(temp_path):
                    os.remove(temp_path)
                    return None, "Image sanitization failed"
                    
                # Move to final location
                os.rename(temp_path, file_path)
            else:
                return None, "Only image files are allowed"
            
            logging.info(f"File uploaded successfully: {safe_filename}")
            return safe_filename, None
            
        except Exception as e:
            logging.error(f"File upload error: {str(e)}")
            if 'temp_path' in locals() and os.path.exists(temp_path):
                os.remove(temp_path)
            return None, "File upload failed"
        
        
def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_super_admin():
            flash("Access denied. Super Admin privileges required.", 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def inventory_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_inventory_admin():
            flash("Access denied. Inventory Admin privileges required.", 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def order_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_order_admin():
            flash("Access denied. Order Admin privileges required.", 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def product_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_product_admin():
            flash("Access denied. Product Admin privileges required.", 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function
        
        

class SSRFProtection:
    def __init__(self):
        self.ALLOWED_DOMAINS = {
            'imgur.com',
            'cloudinary.com',
            'amazonaws.com',
            'googleusercontent.com',
            # Add more trusted domains as needed
        }
        
        self.BLOCKED_IP_RANGES = [
            '127.0.0.0/8',      # Loopback
            '10.0.0.0/8',       # Private network
            '172.16.0.0/12',    # Private network
            '192.168.0.0/16',   # Private network
            '169.254.0.0/16',   # Link-local
            '0.0.0.0/8',        # Invalid addresses
            'fc00::/7',         # Unique local addr
            'fe80::/10',        # Link-local
            '::1/128',          # Loopback
            '100.64.0.0/10',    # Carrier grade NAT
        ]

        self.ALLOWED_SCHEMES = {'https'}
        self.ALLOWED_PORTS = {443, 80}
        self.ALLOWED_CONTENT_TYPES = {
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/webp'
        }

    def is_valid_ip(self, ip_str):
        """Check if IP is valid and not in blocked ranges"""
        try:
            ip = ipaddress.ip_address(ip_str)
            
            # Check if IP is in blocked ranges
            for blocked_range in self.BLOCKED_IP_RANGES:
                if ip in ipaddress.ip_network(blocked_range):
                    return False
                    
            return True
        except ValueError:
            return False

    def is_valid_domain(self, domain):
        """Verify domain against whitelist"""
        return any(domain.lower().endswith(allowed_domain) for allowed_domain in self.ALLOWED_DOMAINS)

    def is_valid_port(self, port):
        """Verify port number"""
        try:
            port_num = int(port) if port else 443
            return port_num in self.ALLOWED_PORTS
        except ValueError:
            return False

    def sanitize_url(self, url):
        """Remove any potentially dangerous characters from URL"""
        # Remove whitespace and non-printable characters
        url = "".join(char for char in url if ord(char) >= 32)
        
        # Remove potentially dangerous characters
        url = re.sub(r'[<>\'"]', '', url)
        
        return url.strip()

    def validate_url(self, url):
        """Comprehensive URL validation"""
        try:
            # Basic sanitization
            url = self.sanitize_url(url)
            
            # Parse URL
            parsed = urlparse(url)
            
            # Validate scheme
            if parsed.scheme.lower() not in self.ALLOWED_SCHEMES:
                return False, "Invalid URL scheme. Only HTTPS is allowed."

            # Validate port
            port = parsed.port
            if not self.is_valid_port(port):
                return False, "Invalid port number."

            # Prevent CRLF injection
            if '\r' in url or '\n' in url:
                return False, "Invalid URL containing line breaks."

            # Validate domain
            if not self.is_valid_domain(parsed.netloc):
                return False, "Domain not in whitelist."

            # Resolve domain to IP
            try:
                ip = socket.gethostbyname(parsed.netloc)
            except socket.gaierror:
                return False, "Could not resolve domain."

            # Validate IP
            if not self.is_valid_ip(ip):
                return False, "IP address not allowed."

            return True, None

        except Exception as e:
            return False, f"URL validation error: {str(e)}"

    def safe_request(self, url, timeout=5):
        """Make a safe HTTP request with comprehensive checks"""
        try:
            # Validate URL first
            is_valid, error = self.validate_url(url)
            if not is_valid:
                raise ValueError(error)

            # Make request with safety measures
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=False,  # Prevent redirect-based SSRF
                verify=True,  # Verify SSL certificates
                headers={
                    'User-Agent': 'CustomSecureBot/1.0',
                    'Accept': 'image/*'
                }
            )

            # Verify response
            if response.status_code != 200:
                raise ValueError(f"Request failed with status {response.status_code}")

            # Validate content type
            content_type = response.headers.get('Content-Type', '').lower()
            if not any(allowed_type in content_type for allowed_type in self.ALLOWED_CONTENT_TYPES):
                raise ValueError(f"Invalid content type: {content_type}")

            # Check content length
            content_length = int(response.headers.get('Content-Length', 0))
            if content_length > 10 * 1024 * 1024:  # 10MB limit
                raise ValueError("File too large")

            return response.content

        except Exception as e:
            raise ValueError(f"Request failed: {str(e)}")



def register_routes(app, db,bcrypt):

    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'csv'}
    

    # routes.py or a separate helper module

    def get_replacement_products(product_type, price):
        """
        Fetch products from the same subcategory that have the same price.
        
        Args:
            product_type (str): The subcategory type of the product.
            price (float): The price of the original product.
        
        Returns:
            list: A list of product objects that match the criteria.
        """
        model_mapping = {
            'FootwearSubCategory': FootwearSubCategory,
            'ActivewearSubCategory': ActivewearSubCategory,
            'BottomsSubCategory': BottomsSubCategory,
            'OuterwearSubCategory': OuterwearSubCategory,
            'RecoverySubCategory': RecoverySubCategory,
            'AccessoriesSubCategory': AccessoriesSubCategory,
            'SwimwearSubCategory': SwimwearSubCategory,
            'CompressionSubCategory': CompressionSubCategory,
            'SpecialtySportswearSubCategory': SpecialtySportswearSubCategory,
            'ProtectiveGearSubCategory': ProtectiveGearSubCategory
        }
        
        model = model_mapping.get(product_type)
        if not model:
            return []
        
        # Fetch products with the same price and available quantity
        replacement_products = model.query.filter_by(price=price).filter(model.quantity > 0).all()
        
        return replacement_products



    def validate_image(stream):
        try:
            img = Image.open(stream)
            img.verify()
            return True
        except Exception:
            return False

    def optimize_image(image_path, quality=85):
        try:
            img = Image.open(image_path)
            img.save(image_path, optimize=True, quality=quality)
        except Exception as e:
            print(f"Error optimizing image: {e}")

    def allowed_file(filename):
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


    def get_items_for_gender(gender):
        """
        Fetches all items for the specified gender across all subcategories.
        Returns a list of dictionaries containing item details.
        """
        items = []
        
        # Define a list of tuples with subcategory models and their category names
        subcategories = [
            (FootwearSubCategory, 'Footwear'),
            (ActivewearSubCategory, 'Activewear Tops'),
            (BottomsSubCategory, 'Bottoms'),
            (OuterwearSubCategory, 'Outerwear'),
            (RecoverySubCategory, 'Recovery & Wellness'),
            (AccessoriesSubCategory, 'Accessories'),
            (SwimwearSubCategory, 'Swimwear'),
            (CompressionSubCategory, 'Compression Wear'),
            (SpecialtySportswearSubCategory, 'Specialty Sportswear'),
            (ProtectiveGearSubCategory, 'Protective Gear')
        ]
        
        for model, category in subcategories:
            queried_items = model.query.filter_by(for_gender=gender).all()
            for item in queried_items:
                items.append({
                    'category': category,
                    'type': item.type,
                    'price': item.price,
                    'size': item.size,
                    'quantity': item.quantity,
                    'product_id': item.id,               # Ensure 'id' is correct
                    'product_type': model.__name__,      # e.g., 'FootwearSubCategory'
                    'image': item.image if item.image else 'default.jpg'  # Use image field
                })
        
        return items

    
    @app.route('/')
    def index():
        # Fetch active promotions
        active_promotions = Promotion.query.filter_by(active=True).all()
        # Optionally, filter promotions based on date
        active_promotions = [promo for promo in active_promotions if promo.is_active()]
        return render_template('index.html', promotions=active_promotions)



    @app.route("/my_returns", methods=["GET"])
    @login_required
    def my_returns():
        return_requests = ReturnRequest.query.filter_by(user_id=current_user.uid).order_by(ReturnRequest.request_date.desc()).all()
        return render_template("my_returns.html", return_requests=return_requests)





    @app.route("/my_orders", methods=["GET"])
    @login_required
    def view_orders():
        """
        Route to display the current user's orders (invoices) along with any associated return requests.
        """
        # Fetch all invoices associated with the current user, ordered by date descending
        invoices = Invoice.query.filter_by(user_id=current_user.uid).order_by(Invoice.date.desc()).all()
        
        # For each invoice, check if there's an associated return request
        invoices_with_returns = []
        for invoice in invoices:
            return_request = ReturnRequest.query.filter_by(invoice_id=invoice.invoice_id).first()
            invoices_with_returns.append({
                'invoice': invoice,
                'return_request': return_request
            })
        
        return render_template("my_orders.html", invoices_with_returns=invoices_with_returns)





    @app.route("/request_return/<int:invoice_id>", methods=["GET", "POST"])
    @login_required
    def request_return(invoice_id):
        invoice = Invoice.query.get_or_404(invoice_id)
        
        # Ensure the invoice belongs to the current user
        if invoice.user_id != current_user.uid:
            flash("You are not authorized to request a return for this invoice.", "danger")
            return redirect(url_for("view_orders"))
        
        # Check if there's already a return request
        existing_return = ReturnRequest.query.filter_by(invoice_id=invoice.invoice_id).first()
        if existing_return:
            flash("A return request for this invoice already exists.", "info")
            return redirect(url_for("view_orders"))
        
        if request.method == "POST":
            product_id = invoice.product_id
            product_type = invoice.product_type
            reason = request.form.get("reason")
            refund_or_replace = request.form.get("action")  # 'refund' or 'replace'
            replacement_product_id = request.form.get("replacement_product_id") if refund_or_replace == "replace" else None
            quantity = request.form.get("quantity", type=int)
            
            # Input validation
            if not reason or refund_or_replace not in ["refund", "replace"]:
                flash("Invalid input. Please provide a reason and select an action.", "danger")
                return redirect(url_for("request_return", invoice_id=invoice_id))
            
            if quantity < 1 or quantity > invoice.quantity:
                flash(f"Invalid quantity. You can return between 1 and {invoice.quantity} items.", "danger")
                return redirect(url_for("request_return", invoice_id=invoice_id))
            
            # If replacing, ensure the replacement product is valid and available
            if refund_or_replace == "replace":
                replacement_product = None
                # Determine the model based on product_type
                model_mapping = {
                    'FootwearSubCategory': FootwearSubCategory,
                    'ActivewearSubCategory': ActivewearSubCategory,
                    'BottomsSubCategory': BottomsSubCategory,
                    'OuterwearSubCategory': OuterwearSubCategory,
                    'RecoverySubCategory': RecoverySubCategory,
                    'AccessoriesSubCategory': AccessoriesSubCategory,
                    'SwimwearSubCategory': SwimwearSubCategory,
                    'CompressionSubCategory': CompressionSubCategory,
                    'SpecialtySportswearSubCategory': SpecialtySportswearSubCategory,
                    'ProtectiveGearSubCategory': ProtectiveGearSubCategory
                }
                model = model_mapping.get(product_type)
                if model:
                    replacement_product = model.query.get(replacement_product_id)
                    if not replacement_product or replacement_product.quantity < quantity:
                        flash("Selected replacement product is not available or insufficient stock.", "danger")
                        return redirect(url_for("request_return", invoice_id=invoice_id))
                else:
                    flash("Invalid product type.", "danger")
                    return redirect(url_for("request_return", invoice_id=invoice_id))
            
            # Calculate refund amount (assuming full refund; modify as needed)
            refund_amount = invoice.total_price if refund_or_replace == "refund" else None
            
            # Create a new ReturnRequest
            new_return = ReturnRequest(
                invoice_id=invoice.invoice_id,
                user_id=current_user.uid,
                product_id=product_id,
                product_type=product_type,
                reason=reason,
                refund_amount=refund_amount,
                replacement_product_id=replacement_product_id,
                quantity=quantity  # **Set the quantity**
            )
            
            db.session.add(new_return)
            db.session.commit()
            
            flash("Your return request has been submitted successfully.", "success")
            return redirect(url_for("view_orders"))
        
        # For GET request, fetch available replacement products with the same price
        model_mapping = {
            'FootwearSubCategory': FootwearSubCategory,
            'ActivewearSubCategory': ActivewearSubCategory,
            'BottomsSubCategory': BottomsSubCategory,
            'OuterwearSubCategory': OuterwearSubCategory,
            'RecoverySubCategory': RecoverySubCategory,
            'AccessoriesSubCategory': AccessoriesSubCategory,
            'SwimwearSubCategory': SwimwearSubCategory,
            'CompressionSubCategory': CompressionSubCategory,
            'SpecialtySportswearSubCategory': SpecialtySportswearSubCategory,
            'ProtectiveGearSubCategory': ProtectiveGearSubCategory
        }
        model = model_mapping.get(invoice.product_type)
        available_replacements = []
        if model:
            # Fetch products of the same subcategory with the same price and available stock
            available_replacements = model.query.filter_by(price=invoice.price).filter(model.quantity >= 1).all()
        
        return render_template("request_return.html", invoice=invoice, available_replacements=available_replacements)



    @app.route("/messi/admin/returns", methods=["GET"])
    @login_required
    def view_returns():
        if current_user.uid != 1:
            flash("Access denied. Admins only.", "danger")
            return redirect(url_for("index"))
        
        return_requests = ReturnRequest.query.order_by(ReturnRequest.request_date.desc()).all()
        return render_template("admin_returns.html", return_requests=return_requests)





    @app.route("/messi/admin/process_return/<int:return_id>", methods=["POST"])
    @login_required
    def process_return(return_id):
        # Ensure the user is an admin
        if current_user.uid != 1:  # Assuming uid=1 is the admin
            flash("Access denied. Admins only.", "danger")
            return redirect(url_for("index"))
        
        return_request = ReturnRequest.query.get_or_404(return_id)
        
        action = request.form.get("action")  # 'approve' or 'deny'
        
        if action not in ["approve", "deny"]:
            flash("Invalid action.", "danger")
            return redirect(url_for("view_returns"))
        
        if action == "approve":
            # Update the return request status
            return_request.status = "Approved"
            
            # Fetch the associated invoice
            invoice = return_request.invoice
            
            # Fetch the product being returned
            product = return_request.get_product()
            if not product:
                flash("Associated product not found.", "danger")
                return redirect(url_for("view_returns"))
            
            # Restore the product's quantity
            product.quantity += return_request.quantity  # **Restoring Quantity**
            
            # If replacement is requested
            if return_request.replacement_product_id:
                # Fetch the replacement product
                replacement_product = None
                model_mapping = {
                    'FootwearSubCategory': FootwearSubCategory,
                    'ActivewearSubCategory': ActivewearSubCategory,
                    'BottomsSubCategory': BottomsSubCategory,
                    'OuterwearSubCategory': OuterwearSubCategory,
                    'RecoverySubCategory': RecoverySubCategory,
                    'AccessoriesSubCategory': AccessoriesSubCategory,
                    'SwimwearSubCategory': SwimwearSubCategory,
                    'CompressionSubCategory': CompressionSubCategory,
                    'SpecialtySportswearSubCategory': SpecialtySportswearSubCategory,
                    'ProtectiveGearSubCategory': ProtectiveGearSubCategory
                }
                model = model_mapping.get(return_request.product_type)
                if model:
                    replacement_product = model.query.get(return_request.replacement_product_id)
                    if replacement_product and replacement_product.quantity > 0:
                        # Deduct stock for replacement product
                        replacement_product.quantity -= return_request.quantity
                        # Optionally, update the invoice status to 'Replaced'
                        invoice.status = "Replaced"
                        flash(f"Replacement product '{replacement_product.type}' issued successfully for Return ID {return_id}.", "success")
                    else:
                        flash("Replacement product is no longer available.", "danger")
                        # Optionally, set status back to 'Pending' or 'Denied'
                        return_request.status = "Denied"
                else:
                    flash("Invalid product type for replacement.", "danger")
                    return_request.status = "Denied"
            
            elif return_request.refund_amount:
                # Process refund logic (e.g., integrate with payment gateway)
                # For demonstration, we'll assume refund is successful
                invoice.status = "Refunded"
                flash(f"Refund of ${return_request.refund_amount:.2f} issued successfully for Return ID {return_id}.", "success")
            
            # Mark the return request as completed
            return_request.status = "Completed"
            
            db.session.commit()
            
            # Optionally, send notification to the user about the approval
            # send_email(...)  # Implement email notifications as needed
        
        elif action == "deny":
            # Update the return request status
            return_request.status = "Denied"
            db.session.commit()
            flash(f"Return Request ID {return_id} has been denied.", "info")
            
            # Optionally, send notification to the user about the denial
            # send_email(...)  # Implement email notifications as needed
        
        return redirect(url_for("view_returns"))






    
    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'GET':
            return render_template('signup.html')
        elif request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            hashed_password = bcrypt.generate_password_hash(password)
            user = User(username=username, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('login'))
        
    @app.route('/product/<product_type>/<int:product_id>')
    def product_detail(product_type, product_id):
        model = globals().get(product_type)
        if not model:
            flash('Invalid product type.', 'danger')
            return redirect(url_for('index'))
        product = model.query.get_or_404(product_id)
        # Check if there's an active promotion for this product
        promotion = Promotion.query.filter_by(product_type=product_type, product_id=product_id, active=True).first()
        if promotion and not promotion.is_active():
            promotion = None

        if current_user.is_authenticated:
        # Assuming you have a Cart model related to the user
            cart_count = Cart.query.filter_by(user_id=current_user.uid).count()
        else:
            cart_count = 0
        return render_template('product_detail.html', product=product, promotion=promotion, cart_count=cart_count)

    @app.route('/messi/admin/inventory')
    @inventory_admin_required
    def inventory_admin_dashboard():
        footwear = Footwear.query.all()
        activewear_tops = ActivewearTops.query.all()
        bottoms = Bottoms.query.all()
        outerwear = Outerwear.query.all()
        recovery_and_wellness = RecoveryAndWellness.query.all()
        accessories = Accessories.query.all()
        swimwear = Swimwear.query.all()
        compression_wear = CompressionWear.query.all()
        specialty_sportswear = SpecialtySportswear.query.all()
        protective_gear = ProtectiveGear.query.all()
        
        return render_template('inventory_admin.html',
            footwear=footwear,
            activewear_tops=activewear_tops,
            bottoms=bottoms,
            outerwear=outerwear,
            recovery_and_wellness=recovery_and_wellness,
            accessories=accessories,
            swimwear=swimwear,
            compression_wear=compression_wear,
            specialty_sportswear=specialty_sportswear,
            protective_gear=protective_gear
        )
    
    @app.route('/messi/admin/orders')
    @order_admin_required
    def order_admin_dashboard():
        try:
            # Get filter parameters
            status = request.args.get('status')
            date_from = request.args.get('date_from')
            date_to = request.args.get('date_to')
            
            # Base query with join to User
            query = Invoice.query.join(User, Invoice.user_id == User.uid)

            # Apply filters
            if status:
                query = query.filter(Invoice.status == status)
            if date_from:
                query = query.filter(Invoice.date >= datetime.strptime(date_from, '%Y-%m-%d'))
            if date_to:
                query = query.filter(Invoice.date <= datetime.strptime(date_to + ' 23:59:59', '%Y-%m-%d %H:%M:%S'))

            # Get invoices
            invoices = query.order_by(Invoice.date.desc()).all()
            
            # Calculate statistics
            total_orders = len(invoices)
            total_revenue = sum(invoice.total_price for invoice in invoices)
            
            # Count orders by status
            status_counts = {
                'Pending': sum(1 for i in invoices if i.status == 'Pending'),
                'Processing': sum(1 for i in invoices if i.status == 'Processing'),
                'Shipped': sum(1 for i in invoices if i.status == 'Shipped'),
                'Delivered': sum(1 for i in invoices if i.status == 'Delivered'),
                'Cancelled': sum(1 for i in invoices if i.status == 'Cancelled'),
                'Paid': sum(1 for i in invoices if i.status == 'Paid')
            }

            return render_template('order_admin.html',
                            invoices=invoices,
                            total_orders=total_orders,
                            total_revenue=total_revenue,
                            status_counts=status_counts)
                            
        except Exception as e:
            print(f"Error in order_admin_dashboard: {e}")
            return render_template('order_admin.html', 
                            invoices=[],
                            total_orders=0,
                            total_revenue=0,
                            status_counts={})

    @app.route('/api/order-details/<int:invoice_id>')
    @order_admin_required
    def get_order_details(invoice_id):
        try:
            invoice = Invoice.query.get_or_404(invoice_id)
            user = User.query.get(invoice.user_id)
            product = invoice.get_product()
            
            # Get status history
            status_history = InvoiceStatusHistory.query\
                .filter_by(invoice_id=invoice_id)\
                .order_by(InvoiceStatusHistory.timestamp.desc())\
                .all()
            
            history_data = [{
                'old_status': h.old_status,
                'new_status': h.new_status,
                'timestamp': h.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'notes': h.notes,
                'updated_by': User.query.get(h.updated_by).username if h.updated_by else None
            } for h in status_history]

            data = {
                'invoice_id': invoice.invoice_id,
                'user_name': user.username if user else 'Unknown User',
                'user_id': user.uid if user else None,
                'product_name': product.type if product else 'Unknown Product',
                'product_size': product.size if product and hasattr(product, 'size') else None,
                'quantity': invoice.quantity,
                'price_per_unit': float(invoice.price),
                'total_price': float(invoice.total_price),
                'status': invoice.status,
                'date': invoice.date.strftime('%Y-%m-%d %H:%M:%S'),
                'notes': invoice.notes,
                'shipping_address': invoice.shipping_address,
                'tracking_number': invoice.tracking_number,
                'payment_status': invoice.payment_status,
                'payment_method': invoice.payment_method,
                'status_history': history_data
            }
            
            return jsonify(data)
            
        except Exception as e:
            print(f"Error in get_order_details: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/messi/admin/orders/update_status', methods=['POST'])
    @order_admin_required
    def update_order_status():
        try:
            invoice_id = request.form.get('invoice_id')
            new_status = request.form.get('new_status')
            notes = request.form.get('notes')

            if not invoice_id or not new_status:
                return jsonify({'error': 'Order ID and new status are required.'}), 400

            # Validate status
            valid_statuses = ['Pending', 'Processing', 'Shipped', 'Delivered', 'Cancelled', 'Paid']
            if new_status not in valid_statuses:
                return jsonify({'error': 'Invalid status selected.'}), 400

            invoice = Invoice.query.get_or_404(invoice_id)
            
            # Check if status update is valid
            can_update, error_message = invoice.can_update_status(new_status)
            if not can_update:
                return jsonify({'error': error_message}), 400

            # Update the status
            invoice.update_status(new_status, notes, current_user.uid)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f'Order status updated to {new_status}',
                'new_status': new_status,
                'updated_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            }), 200

        except Exception as e:
            db.session.rollback()
            print(f"Error in update_order_status: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/messi/admin/orders/export', methods=['POST'])
    @order_admin_required
    def export_orders():
        try:
            # Get filter parameters
            status = request.form.get('status')
            date_from = request.form.get('date_from')
            date_to = request.form.get('date_to')
            
            # Base query with joins
            query = Invoice.query.join(User, Invoice.user_id == User.uid)

            # Apply filters
            if status:
                query = query.filter(Invoice.status == status)
            if date_from:
                query = query.filter(Invoice.date >= datetime.strptime(date_from, '%Y-%m-%d'))
            if date_to:
                query = query.filter(Invoice.date <= datetime.strptime(date_to + ' 23:59:59', '%Y-%m-%d %H:%M:%S'))

            # Get invoices
            invoices = query.order_by(Invoice.date.desc()).all()

            # Create CSV in memory
            output = StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                'Order ID',
                'Date',
                'Customer',
                'Product Type',
                'Product Name',
                'Quantity',
                'Unit Price',
                'Total Price',
                'Status',
                'Shipping Address',
                'Tracking Number',
                'Payment Status',
                'Payment Method',
                'Notes'
            ])
            
            # Write data
            for invoice in invoices:
                product = invoice.get_product()
                product_name = product.type if product else 'Unknown Product'
                
                writer.writerow([
                    invoice.invoice_id,
                    invoice.date.strftime('%Y-%m-%d %H:%M:%S'),
                    invoice.user.username,
                    invoice.product_type,
                    product_name,
                    invoice.quantity,
                    f"${invoice.price:.2f}",
                    f"${invoice.total_price:.2f}",
                    invoice.status,
                    invoice.shipping_address or '',
                    invoice.tracking_number or '',
                    invoice.payment_status or 'Pending',
                    invoice.payment_method or '',
                    invoice.notes or ''
                ])
            
            # Prepare response
            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={
                    'Content-Disposition': f'attachment;filename=orders_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
                    'Content-Type': 'text/csv; charset=utf-8'
                }
            )
            
        except Exception as e:
            print(f"Export error: {e}")
            return jsonify({'error': 'Failed to export orders'}), 500


    @app.route('/messi/admin/products')
    @product_admin_required
    def product_admin_dashboard():
        footwear_subcategories = FootwearSubCategory.query.all()
        activewear_subcategories = ActivewearSubCategory.query.all()
        bottoms_subcategories = BottomsSubCategory.query.all()
        outerwear_subcategories = OuterwearSubCategory.query.all()
        recovery_subcategories = RecoverySubCategory.query.all()
        accessories_subcategories = AccessoriesSubCategory.query.all()
        swimwear_subcategories = SwimwearSubCategory.query.all()
        compression_subcategories = CompressionSubCategory.query.all()
        specialty_sportswear_subcategories = SpecialtySportswearSubCategory.query.all()
        protective_gear_subcategories = ProtectiveGearSubCategory.query.all()
        
        return render_template('product_admin.html',
            footwear_subcategories=footwear_subcategories,
            activewear_subcategories=activewear_subcategories,
            bottoms_subcategories=bottoms_subcategories,
            outerwear_subcategories=outerwear_subcategories,
            recovery_subcategories=recovery_subcategories,
            accessories_subcategories=accessories_subcategories,
            swimwear_subcategories=swimwear_subcategories,
            compression_subcategories=compression_subcategories,
            specialty_sportswear_subcategories=specialty_sportswear_subcategories,
            protective_gear_subcategories=protective_gear_subcategories
        )



    @app.route('/messi/admin/promotions')
    @login_required
    def manage_promotions():
        promotions = Promotion.query.order_by(Promotion.start_date.desc()).all()
        return render_template('admin_promotions.html', promotions=promotions)

    @app.route('/messi/admin/promotions/add', methods=['GET', 'POST'])
    @login_required
    def add_promotion():
        if request.method == 'POST':
            product_type = request.form.get('product_type')
            product_id = request.form.get('product_id', type=int)
            discounted_price = request.form.get('discounted_price', type=float)
            start_date = request.form.get('start_date')
            end_date = request.form.get('end_date')

            # Validate input
            if not product_type or not product_id or not discounted_price:
                flash('Please provide all required fields.', 'warning')
                return redirect(url_for('add_promotion'))

            # Fetch the product
            model = globals().get(product_type)
            if not model:
                flash('Invalid product type selected.', 'danger')
                return redirect(url_for('add_promotion'))
            product = model.query.get(product_id)
            if not product:
                flash('Product not found.', 'danger')
                return redirect(url_for('add_promotion'))

            # Determine old price
            if hasattr(product, 'price'):
                old_price = product.price
            else:
                flash('Selected product does not have a price attribute.', 'danger')
                return redirect(url_for('add_promotion'))

            # Create Promotion
            promotion = Promotion(
                product_type=product_type,
                product_id=product_id,
                old_price=old_price,
                discounted_price=discounted_price,
                start_date=datetime.strptime(start_date, '%Y-%m-%d') if start_date else datetime.utcnow(),
                end_date=datetime.strptime(end_date, '%Y-%m-%d') if end_date else None,
                active=True
            )
            db.session.add(promotion)
            db.session.commit()
            flash('Promotion added successfully.', 'success')
            return redirect(url_for('manage_promotions'))

        # GET request
        # Fetch all products to populate the product selection
        # For simplicity, we'll combine all subcategories into a single list
        products = []
        for model in [FootwearSubCategory, ActivewearSubCategory, BottomsSubCategory, OuterwearSubCategory, RecoverySubCategory, AccessoriesSubCategory, SwimwearSubCategory, CompressionSubCategory, SpecialtySportswearSubCategory, ProtectiveGearSubCategory]:
            for product in model.query.all():
                products.append({'type': model._name_, 'id': product.id, 'name': product.type})

        return render_template('add_promotion.html', products=products)

    @app.route('/messi/admin/promotions/remove/<int:promotion_id>', methods=['POST'])
    @login_required
    def remove_promotion(promotion_id):
        promotion = Promotion.query.get_or_404(promotion_id)
        db.session.delete(promotion)
        db.session.commit()
        flash('Promotion removed successfully.', 'success')
        return redirect(url_for('manage_promotions'))

    @app.route('/messi/admin/promotions/deactivate/<int:promotion_id>', methods=['POST'])
    @login_required
    def deactivate_promotion(promotion_id):
        promotion = Promotion.query.get_or_404(promotion_id)
        promotion.active = False
        db.session.commit()
        flash('Promotion deactivated successfully.', 'success')
        return redirect(url_for('manage_promotions'))



    @app.route('/messi/admin/bulk_upload', methods=['POST'])
    @login_required
    def bulk_upload():
        if current_user.uid != 1:
            flash("Access denied. Admins only.", 'danger')
            return redirect(url_for('index'))

        if 'bulk_csv' not in request.files:
            flash("No file part in the request.", 'danger')
            return redirect(url_for('admin'))

        file = request.files['bulk_csv']
        file_handler = SecureFileUpload()
        ssrf_protection = SSRFProtection()

        if file.filename == '':
            flash("No file selected.", 'danger')
            return redirect(url_for('admin'))

        if not file_handler.allowed_file(file.filename):
            flash("Invalid file type. Please upload a CSV file.", 'danger')
            return redirect(url_for('admin'))

        try:
            # Validate file size
            content = file.read()
            if len(content) > 5 * 1024 * 1024:  # 5MB limit
                flash("File size too large.", 'danger')
                return redirect(url_for('admin'))
            
            file.seek(0)
            
            # Read CSV content safely
            stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_input = csv.DictReader(stream)

            required_fields = ['main_category', 'type', 'price', 'size', 'quantity', 'for_gender', 'image_url']
            for field in required_fields:
                if field not in csv_input.fieldnames:
                    flash(f"Missing required field: {field}", 'danger')
                    return redirect(url_for('admin'))

            success_count = 0
            failure_count = 0
            failure_messages = []

            # Your existing category mappings
            main_category_models = {
                'footwear': FootwearSubCategory,
                'activewear_tops': ActivewearSubCategory,
                'bottoms': BottomsSubCategory,
                'outerwear': OuterwearSubCategory,
                'recovery_and_wellness': RecoverySubCategory,
                'accessories': AccessoriesSubCategory,
                'swimwear': SwimwearSubCategory,
                'compression_wear': CompressionSubCategory,
                'specialty_sportswear': SpecialtySportswearSubCategory,
                'protective_gear': ProtectiveGearSubCategory
            }

            main_category_table = {
                'footwear': Footwear,
                'activewear_tops': ActivewearTops,
                'bottoms': Bottoms,
                'outerwear': Outerwear,
                'recovery_and_wellness': RecoveryAndWellness,
                'accessories': Accessories,
                'swimwear': Swimwear,
                'compression_wear': CompressionWear,
                'specialty_sportswear': SpecialtySportswear,
                'protective_gear': ProtectiveGear
            }

            foreign_key_mapping = {
                'footwear': 'footwear_id',
                'activewear_tops': 'activewear_id',
                'bottoms': 'bottoms_id',
                'outerwear': 'outerwear_id',
                'recovery_and_wellness': 'recovery_id',
                'accessories': 'accessories_id',
                'swimwear': 'swimwear_id',
                'compression_wear': 'compression_wear_id',
                'specialty_sportswear': 'specialty_sportswear_id',
                'protective_gear': 'protective_gear_id'
            }

            for idx, row in enumerate(csv_input, start=1):
                try:
                    # Basic data validation
                    main_category = row['main_category'].strip().lower()
                    product_type = row['type'].strip()
                    price = row['price'].strip()
                    size = row['size'].strip()
                    quantity = row['quantity'].strip()
                    for_gender = row['for_gender'].strip()
                    image_url = row.get('image_url', '').strip()

                    # Validate main_category
                    SubCategoryModel = main_category_models.get(main_category)
                    MainCategoryModel = main_category_table.get(main_category)
                    foreign_key_field = foreign_key_mapping.get(main_category)

                    if not all([SubCategoryModel, MainCategoryModel, foreign_key_field]):
                        raise ValueError(f"Invalid main category '{main_category}'")

                    # Price validation
                    try:
                        price = float(price)
                        if price < 0:
                            raise ValueError("Price cannot be negative")
                    except ValueError:
                        raise ValueError(f"Invalid price '{row['price']}'")

                    # Quantity validation
                    try:
                        quantity = int(quantity)
                        if quantity < 0:
                            raise ValueError("Quantity cannot be negative")
                    except ValueError:
                        raise ValueError(f"Invalid quantity '{row['quantity']}'")

                    # Gender validation
                    if for_gender not in ['Men', 'Women', 'Kids']:
                        raise ValueError(f"Invalid gender '{for_gender}'")

                    # Image handling with SSRF protection
                    if image_url:
                        try:
                            # Validate URL
                            is_valid, error = ssrf_protection.validate_url(image_url)
                            if not is_valid:
                                raise ValueError(f"Invalid image URL: {error}")

                            # Download image safely
                            image_content = ssrf_protection.safe_request(image_url)
                            
                            # Generate secure filename
                            image_filename = secure_filename(os.path.basename(image_url))
                            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                            unique_filename = f"{timestamp}_{uuid.uuid4().hex}_{image_filename}"
                            
                            # Set up storage path
                            category_folder = os.path.join(app.root_path, 'static', 'images', 
                                                        main_category.lower())
                            os.makedirs(category_folder, exist_ok=True)
                            image_path = os.path.join(category_folder, unique_filename)

                            # Save and verify image
                            with open(image_path, 'wb') as f:
                                f.write(image_content)

                            # Verify saved image
                            with Image.open(image_path) as img:
                                img.verify()
                                if img.format not in ['JPEG', 'PNG', 'GIF']:
                                    os.remove(image_path)
                                    raise ValueError("Invalid image format")

                            image_relative_path = f"{main_category.lower()}/{unique_filename}"

                        except Exception as e:
                            raise ValueError(f"Image processing failed: {str(e)}")
                    else:
                        image_relative_path = "default.jpg"

                    # Database operations with transaction
                    with db.session.begin_nested():
                        # Get or create main category
                        main_category_entry = MainCategoryModel.query.filter_by(type=product_type).first()
                        if not main_category_entry:
                            main_category_entry = MainCategoryModel(type=product_type, quantity=0)
                            db.session.add(main_category_entry)
                            db.session.flush()

                        # Create product with validated data
                        product_data = {
                            "type": product_type,
                            "price": price,
                            "size": size,
                            "quantity": quantity,
                            "for_gender": for_gender,
                            "image": image_relative_path,
                            foreign_key_field: main_category_entry.id
                        }

                        new_product = SubCategoryModel(**product_data)
                        db.session.add(new_product)
                        
                        # Update main category quantity
                        main_category_entry.quantity += quantity

                    success_count += 1

                except Exception as e:
                    failure_count += 1
                    failure_messages.append(f"Row {idx}: {str(e)}")
                    continue

            # Final commit for successful operations
            try:
                db.session.commit()
                flash(f"Bulk Upload Completed: {success_count} succeeded, {failure_count} failed.", 'info')
                for message in failure_messages:
                    flash(message, 'warning')
            except Exception as e:
                db.session.rollback()
                flash(f"Database error during final commit: {str(e)}", 'danger')

            return redirect(url_for('admin'))

        except Exception as e:
            print(f"Bulk upload error: {e}")
            flash("An error occurred while processing the CSV file.", 'danger')
            return redirect(url_for('admin'))
    

            
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'GET':
            return render_template('login.html')
        elif request.method == 'POST':
            try:
                user_data = request.get_json()
                if not user_data or 'username' not in user_data or 'password' not in user_data:
                    return jsonify({'error': 'Missing username or password'}), 400

                username = user_data["username"]
                password = user_data["password"]

                existing_user = User.query.filter_by(username=username).first()
                if existing_user is None:
                    return jsonify({'error': 'Invalid credentials'}), 403

                if not bcrypt.check_password_hash(existing_user.password, password):
                    return jsonify({'error': 'Invalid credentials'}), 403

                token = create_token(existing_user.uid, app)
                login_user(existing_user)
                return jsonify({"token": token}), 200
            except:
                return "error"
    
    
    @app.route('/logout')
    def logout():
        logout_user()
        return redirect(url_for('index'))
    


    ######admin page
   # routes.py

    # routes.py

    @app.route('/messi/admin')
    @login_required
    def admin():
        if current_user.uid != 1:
            flash("Access denied. Admins only.", 'danger')
            return redirect(url_for('index'))
        
        if not any([
            current_user.is_super_admin(),
            current_user.is_inventory_admin(),
            current_user.is_order_admin(),
            current_user.is_product_admin()
        ]):
            flash("Access denied. Admin privileges required.", 'danger')
            return redirect(url_for('index'))

        # Fetch all users and product categories
        if current_user.is_super_admin():
            users = User.query.all()
            footwear = Footwear.query.all()
            activewear_tops = ActivewearTops.query.all()
            bottoms = Bottoms.query.all()
            outerwear = Outerwear.query.all()
            recovery_and_wellness = RecoveryAndWellness.query.all()
            accessories = Accessories.query.all()
            swimwear = Swimwear.query.all()
            compression_wear = CompressionWear.query.all()
            specialty_sportswear = SpecialtySportswear.query.all()
            protective_gear = ProtectiveGear.query.all()
            invoices = Invoice.query.order_by(Invoice.date.desc()).all()

            # Subcategories
            footwear_subcategories = FootwearSubCategory.query.all()
            activewear_subcategories = ActivewearSubCategory.query.all()
            bottoms_subcategories = BottomsSubCategory.query.all()
            outerwear_subcategories = OuterwearSubCategory.query.all()
            recovery_subcategories = RecoverySubCategory.query.all()
            accessories_subcategories = AccessoriesSubCategory.query.all()
            swimwear_subcategories = SwimwearSubCategory.query.all()
            compression_subcategories = CompressionSubCategory.query.all()
            specialty_sportswear_subcategories = SpecialtySportswearSubCategory.query.all()
            protective_gear_subcategories = ProtectiveGearSubCategory.query.all()

            # Prepare subcategories data
            subcategories_data = {
                # ... (existing code)
            }

            return render_template('admin.html',
                users=users,
                footwear=footwear,
                activewear_tops=activewear_tops,
                bottoms=bottoms,
                outerwear=outerwear,
                recovery_and_wellness=recovery_and_wellness,
                accessories=accessories,
                swimwear=swimwear,
                compression_wear=compression_wear,
                specialty_sportswear=specialty_sportswear,
                protective_gear=protective_gear,
                footwear_subcategories=footwear_subcategories,
                activewear_subcategories=activewear_subcategories,
                bottoms_subcategories=bottoms_subcategories,
                outerwear_subcategories=outerwear_subcategories,
                recovery_subcategories=recovery_subcategories,
                accessories_subcategories=accessories_subcategories,
                swimwear_subcategories=swimwear_subcategories,
                compression_subcategories=compression_subcategories,
                specialty_sportswear_subcategories=specialty_sportswear_subcategories,
                protective_gear_subcategories=protective_gear_subcategories,
                invoices=invoices,
                subcategories_data=subcategories_data
            )
    
    @app.route('/messi/admin/create_user', methods=['GET', 'POST'])
    @super_admin_required
    def create_user():
        if request.method == 'GET':
            return render_template('create_admin.html')
            
        try:
            # Get form data
            username = request.form.get('username')
            password = request.form.get('password')
            role = request.form.get('role')
            description = request.form.get('description')

            # Validate inputs
            if not username or not password:
                flash('Username and password are required.', 'danger')
                return redirect(url_for('create_user'))

            # Check if username already exists
            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'danger')
                return redirect(url_for('create_user'))

            # Validate role
            valid_roles = [
                User.ROLE_SUPER_ADMIN,
                User.ROLE_INVENTORY_ADMIN,
                User.ROLE_ORDER_ADMIN,
                User.ROLE_PRODUCT_ADMIN,
                'user'
            ]
            if role not in valid_roles:
                flash('Invalid role specified.', 'danger')
                return redirect(url_for('create_user'))

            # Create new user
            hashed_password = bcrypt.generate_password_hash(password)
            new_user = User(
                username=username,
                password=hashed_password,
                role=role,
                description=description
            )
            db.session.add(new_user)
            db.session.commit()

            flash(f'User {username} created successfully with role: {role}', 'success')
            return redirect(url_for('admin'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'danger')
            return redirect(url_for('create_user'))
        


    # Route to Edit Item Price
    @app.route('/admin/edit_item', methods=['POST'])
    @login_required
    def edit_item():
        if current_user.uid != 1:
            flash("Access denied. Admins only.", 'danger')
            return redirect(url_for('index'))
        
        product_type = request.form.get('product_type')
        item_id = request.form.get('item_id')
        new_price = request.form.get('new_price')
        new_image = request.files.get('new_image')  # Get the uploaded image file

        if not all([product_type, item_id, new_price]):
            flash("Product type, item ID, and new price are required.", 'danger')
            return redirect(url_for('admin'))

        try:
            new_price = float(new_price)
            if new_price < 0:
                flash("Price cannot be negative.", 'danger')
                return redirect(url_for('admin'))
        except ValueError:
            flash("Invalid price format.", 'danger')
            return redirect(url_for('admin'))
        
        # Map product_type to the corresponding model
        model_mapping = {
            'footwear': Footwear,
            'footwear_subcategory': FootwearSubCategory,
            'activewear_tops': ActivewearTops,
            'activewear_subcategory': ActivewearSubCategory,
            'bottoms': Bottoms,
            'bottoms_subcategory': BottomsSubCategory,
            'outerwear': Outerwear,
            'outerwear_subcategory': OuterwearSubCategory,
            'recovery_and_wellness': RecoveryAndWellness,
            'recovery_subcategory': RecoverySubCategory,
            'accessories': Accessories,
            'accessories_subcategory': AccessoriesSubCategory,
            'swimwear': Swimwear,
            'swimwear_subcategory': SwimwearSubCategory,
            'compression_wear': CompressionWear,
            'compression_subcategory': CompressionSubCategory,
            'specialty_sportswear': SpecialtySportswear,
            'specialty_sportswear_subcategory': SpecialtySportswearSubCategory,
            'protective_gear': ProtectiveGear,
            'protective_gear_subcategory': ProtectiveGearSubCategory
        }

        model = model_mapping.get(product_type)
        if not model:
            flash("Invalid product type.", 'danger')
            return redirect(url_for('admin'))
        
        # Query the item
        item = model.query.get(int(item_id))
        if not item:
            flash("Item not found.", 'danger')
            return redirect(url_for('admin'))
        
        # Update the price
        item.price = new_price

        # Handle image upload if a new image is provided
        if new_image and allowed_file(new_image.filename):
            if not validate_image(new_image.stream):
                flash("Uploaded file is not a valid image.", 'danger')
                return redirect(url_for('admin'))
            
            # Reset stream position after validation
            new_image.stream.seek(0)
            
            filename = secure_filename(new_image.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            
            # Determine the main category based on product_type
            # Extract main category from product_type (e.g., 'footwear_subcategory' -> 'footwear')
            main_category_key = product_type.replace('_subcategory', '')
            category_folder = os.path.join(app.root_path, 'static', 'images', main_category_key.lower())
            os.makedirs(category_folder, exist_ok=True)
            
            image_path = os.path.join(category_folder, unique_filename)
            new_image.save(image_path)
            
            # Optimize the image
            optimize_image(image_path)
            
            # Optionally, delete the old image file if it exists and is not default
            if item.image and item.image != 'default.jpg':
                old_image_path = os.path.join(app.root_path, 'static', 'images', item.image)
                if os.path.exists(old_image_path):
                    try:
                        os.remove(old_image_path)
                    except Exception as e:
                        print(f"Error deleting old image: {e}")
            
            # Update the image path in the database
            item.image = f"{main_category_key.lower()}/{unique_filename}"
        
        elif new_image:
            # If an image was uploaded but it's invalid
            flash("Invalid image file.", 'danger')
            return redirect(url_for('admin'))
        
        try:
            db.session.commit()
            flash("Item updated successfully.", 'success')
            return redirect(url_for('admin'))
        except Exception as e:
            print(f"Error updating item: {e}")
            db.session.rollback()
            flash("An error occurred while updating the item.", 'danger')
            return redirect(url_for('admin'))


    # Route to Remove Item
    @app.route('/admin/remove_item', methods=['POST'])
    @login_required
    def remove_item():
        if current_user.uid != 1:
            flash("Access denied. Admins only.", 'danger')
            return redirect(url_for('index'))
        
        product_type = request.form.get('product_type')
        item_id = request.form.get('item_id')

        if not all([product_type, item_id]):
            flash("Invalid data provided for removal.", 'danger')
            return redirect(url_for('admin'))
        
        try:
            # Map product_type to the corresponding model
            model_mapping = {
                'footwear': Footwear,
                'footwear_subcategory': FootwearSubCategory,
                'activewear_tops': ActivewearTops,
                'activewear_subcategory': ActivewearSubCategory,
                'bottoms': Bottoms,
                'bottoms_subcategory': BottomsSubCategory,
                'outerwear': Outerwear,
                'outerwear_subcategory': OuterwearSubCategory,
                'recovery_and_wellness': RecoveryAndWellness,
                'recovery_subcategory': RecoverySubCategory,
                'accessories': Accessories,
                'accessories_subcategory': AccessoriesSubCategory,
                'swimwear': Swimwear,
                'swimwear_subcategory': SwimwearSubCategory,
                'compression_wear': CompressionWear,
                'compression_subcategory': CompressionSubCategory,
                'specialty_sportswear': SpecialtySportswear,
                'specialty_sportswear_subcategory': SpecialtySportswearSubCategory,
                'protective_gear': ProtectiveGear,
                'protective_gear_subcategory': ProtectiveGearSubCategory
            }

            model = model_mapping.get(product_type)
            if not model:
                flash("Invalid product type.", 'danger')
                return redirect(url_for('admin'))
            
            # Query the item
            item = model.query.get(int(item_id))
            if not item:
                flash("Item not found.", 'danger')
                return redirect(url_for('admin'))
            
            # Remove the item
            db.session.delete(item)
            db.session.commit()
            flash(f"{item.type} has been removed successfully.", 'success')
            return redirect(url_for('admin'))
        
        except Exception as e:
            print(f"Error removing item: {e}")
            db.session.rollback()
            flash("An error occurred while removing the item.", 'danger')
            return redirect(url_for('admin'))


    @app.route('/messi/admin/add_product', methods=['POST'])
    @login_required
    def add_product():
        if current_user.uid != 1:
            flash("Access denied. Admins only.", 'danger')
            return redirect(url_for('index'))


        main_category = request.form.get('main_category')
        product_type = request.form.get('type')
        price = request.form.get('price')
        size = request.form.get('size')
        quantity = request.form.get('quantity')
        for_gender = request.form.get('for_gender')
        image_file = request.files.get('image')


        if not all([main_category, product_type, price, size, quantity, for_gender, image_file]):
            flash("All fields are required.", 'danger')
            return redirect(url_for('admin'))


        if image_file and allowed_file(image_file.filename):
            filename = secure_filename(image_file.filename)

            category_folder = os.path.join(app.root_path, 'static', 'images', main_category.lower())
            os.makedirs(category_folder, exist_ok=True)

            image_path = os.path.join(category_folder, filename)
            image_file.save(image_path)
        else:
            flash("Invalid image file.", 'danger')
            return redirect(url_for('admin'))

        try:

            price = float(price)
            quantity = int(quantity)

            if price < 0 or quantity < 0:
                flash("Price and Quantity must be non-negative.", 'danger')
                return redirect(url_for('admin'))

            main_category_models = {
                'footwear': Footwear,
                'activewear_tops': ActivewearTops,
                'bottoms': Bottoms,
                'outerwear': Outerwear,
                'recovery_and_wellness': RecoveryAndWellness,
                'accessories': Accessories,
                'swimwear': Swimwear,
                'compression_wear': CompressionWear,
                'specialty_sportswear': SpecialtySportswear,
                'protective_gear': ProtectiveGear
            }

            subcategory_models = {
                'footwear': FootwearSubCategory,
                'activewear_tops': ActivewearSubCategory,
                'bottoms': BottomsSubCategory,
                'outerwear': OuterwearSubCategory,
                'recovery_and_wellness': RecoverySubCategory,
                'accessories': AccessoriesSubCategory,
                'swimwear': SwimwearSubCategory,
                'compression_wear': CompressionSubCategory,
                'specialty_sportswear': SpecialtySportswearSubCategory,
                'protective_gear': ProtectiveGearSubCategory
            }

            foreign_key_fields = {
                'footwear': 'footwear_id',
                'activewear_tops': 'activewear_id',
                'bottoms': 'bottoms_id',
                'outerwear': 'outerwear_id',
                'recovery_and_wellness': 'recovery_id',
                'accessories': 'accessories_id',
                'swimwear': 'swimwear_id',
                'compression_wear': 'compression_wear_id',
                'specialty_sportswear': 'specialty_sportswear_id',
                'protective_gear': 'protective_gear_id'
            }

            MainCategoryModel = main_category_models.get(main_category)
            SubCategoryModel = subcategory_models.get(main_category)
            foreign_key_field = foreign_key_fields.get(main_category)

            if not MainCategoryModel or not SubCategoryModel or not foreign_key_field:
                flash("Invalid main category selected.", 'danger')
                return redirect(url_for('admin'))

            # Get or create the main category item
            main_category_type = main_category.replace('_', ' ').title()
            main_category_item = MainCategoryModel.query.filter_by(type=main_category_type).first()
            if not main_category_item:
                main_category_item = MainCategoryModel(type=main_category_type, quantity=0)
                db.session.add(main_category_item)
                db.session.commit()

            # Create a new product in the selected subcategory
            new_product_data = {
                foreign_key_field: main_category_item.id,
                'type': product_type,
                'price': price,
                'size': size,
                'quantity': quantity,
                'for_gender': for_gender,
                'image': f"{main_category.lower()}/{filename}"  # Store relative path
            }
            new_product = SubCategoryModel(**new_product_data)

            db.session.add(new_product)
            db.session.commit()
            flash(f"Product '{product_type}' added successfully.", 'success')
            return redirect(url_for('admin'))

        except ValueError:
            flash("Invalid input for price or quantity.", 'danger')
            return redirect(url_for('admin'))
        except Exception as e:
            print(f"Error adding product: {e}")
            db.session.rollback()
            flash("An error occurred while adding the product.", 'danger')
            return redirect(url_for('admin'))



    @app.route('/messi/admin/generate_report', methods=['GET', 'POST'])
    @login_required
    def generate_report():
        if current_user.uid != 1:
            flash('Unauthorized access.', 'danger')
            return redirect(url_for('index'))

        if request.method == 'POST':
            try:
                # 1. Calculate Most Popular Product
                popular_product = db.session.query(
                    Invoice.product_id,
                    Invoice.product_type,
                    func.sum(Invoice.quantity).label('total_quantity')
                ).group_by(
                    Invoice.product_id, 
                    Invoice.product_type
                ).order_by(
                    func.sum(Invoice.quantity).desc()
                ).first()

                if not popular_product:
                    flash('No sales data available to generate report.', 'warning')
                    return redirect(url_for('admin'))

                # 2. Calculate Inventory Turnover
                # Get total sales value
                total_sales = db.session.query(
                    func.sum(Invoice.total_price)
                ).scalar() or 0

                # Get current inventory value (sum of price * quantity for all products)
                total_inventory_value = 0
                for model in [FootwearSubCategory, ActivewearSubCategory, BottomsSubCategory,
                            OuterwearSubCategory, RecoverySubCategory, AccessoriesSubCategory,
                            SwimwearSubCategory, CompressionSubCategory,
                            SpecialtySportswearSubCategory, ProtectiveGearSubCategory]:
                    inventory_value = db.session.query(
                        func.sum(model.price * model.quantity)
                    ).scalar() or 0
                    total_inventory_value += inventory_value

                inventory_turnover = total_sales / total_inventory_value if total_inventory_value > 0 else 0

                # 3. Generate Future Demand Prediction
                # Simple prediction based on sales trends
                thirty_days_ago = datetime.utcnow() - timedelta(days=30)
                recent_sales = db.session.query(
                    func.count(Invoice.invoice_id)
                ).filter(
                    Invoice.date >= thirty_days_ago
                ).scalar() or 0

                if recent_sales > 100:
                    future_demand = "High demand expected. Consider increasing inventory."
                elif recent_sales > 50:
                    future_demand = "Moderate demand expected. Current inventory levels should be sufficient."
                else:
                    future_demand = "Lower demand expected. Consider promotional activities."

                # 4. Create Report
                report = Report(
                    most_popular_product_id=popular_product.product_id,
                    most_popular_product_type=popular_product.product_type,
                    total_quantity=popular_product.total_quantity,
                    inventory_turnover=round(inventory_turnover, 2),
                    future_demand=future_demand
                )

                db.session.add(report)
                db.session.commit()

                flash('Inventory report generated successfully.', 'success')
                return redirect(url_for('view_report', report_id=report.id))

            except Exception as e:
                print(f"Error generating report: {e}")
                flash('An error occurred while generating the report.', 'danger')
                return redirect(url_for('admin'))

        # GET request - show form to generate report
        return render_template('generate_report.html')
    
    @app.route('/messi/admin/view_report/<int:report_id>')
    @login_required
    def view_report(report_id):
        if current_user.uid != 1:  # Ensure only admin can access
            flash('Unauthorized access.', 'danger')
            return redirect(url_for('index'))

        report = Report.query.get_or_404(report_id)
        
        # Get details of the most popular product
        popular_product = None
        if report.most_popular_product_type and report.most_popular_product_id:
            try:
                model = globals()[report.most_popular_product_type]
                popular_product = model.query.get(report.most_popular_product_id)
            except (KeyError, AttributeError):
                pass

        return render_template('view_report.html', 
                            report=report, 
                            popular_product=popular_product)

    @app.route('/men')
    def men():
        from models import Cart  # Local import to avoid circular dependency
        token = extract_auth_token(request)
        user_id = decode_token(token, app)
        men_items = get_items_for_gender('Men')  # Utilize the existing function
        main_categories = [
            'All',
            'Footwear',
            'Activewear Tops',
            'Bottoms',
            'Outerwear',
            'Recovery & Wellness',
            'Accessories',
            'Swimwear',
            'Compression Wear',
            'Specialty Sportswear',
            'Protective Gear'
        ]
        cart_count = Cart.query.filter_by(user_id=current_user.uid).count() if current_user.is_authenticated else 0
        return render_template('men.html', men_items=men_items, main_categories=main_categories, cart_count=cart_count)




    @app.route('/women')
    def women():
        women_items = get_items_for_gender('Women')
        
        # Define main categories for filtering, including 'All'
        main_categories = [
            'All',
            'Footwear',
            'Activewear Tops',
            'Bottoms',
            'Outerwear',
            'Recovery & Wellness',
            'Accessories',
            'Swimwear',
            'Compression Wear',
            'Specialty Sportswear',
            'Protective Gear'
        ]
        
        return render_template('women.html', items=women_items, categories=main_categories)


    @app.route('/kids')
    def kids():
        kids_items = get_items_for_gender('Kids')
        
        # Define main categories for filtering, including 'All'
        main_categories = [
            'All',
            'Footwear',
            'Activewear Tops',
            'Bottoms',
            'Outerwear',
            'Recovery & Wellness',
            'Accessories',
            'Swimwear',
            'Compression Wear',
            'Specialty Sportswear',
            'Protective Gear'
        ]
        
        return render_template('kids.html', items=kids_items, categories=main_categories)



    @app.route("/add_to_cart", methods=["POST"])
    @login_required
    def add_to_cart():
        token = extract_auth_token(request)
        user_id = decode_token(token, app)
        
        try:
            # Get data from request JSON instead of token decode
            data = request.get_json()
            print("Received data in /add_to_cart:", data)  # Debugging line

            product_id = data.get('product_id')
            product_type = data.get('product_type')
            quantity = data.get('quantity', 1)

            if not product_id or not product_type:
                return jsonify({'error': 'Product ID and type are required.'}), 400

            # Local import to avoid circular dependency
            from models import Cart, Promotion

            # Validate product_type corresponds to a valid model
            product_model = globals().get(product_type)
            if not product_model:
                return jsonify({'error': 'Invalid product type.'}), 400

            # Check if the product exists
            product = product_model.query.get(product_id)
            if not product:
                return jsonify({'error': 'Product not found.'}), 404

            if product.quantity < quantity:
                return jsonify({'error': 'Requested quantity exceeds available stock.'}), 400

            # Check for active promotion
            promotion = Promotion.query.filter_by(
                product_type=product_type,
                product_id=product_id,
                active=True
            ).first()

            # Determine the correct price
            price_to_use = promotion.discounted_price if promotion and promotion.is_active() else product.price

            # Check if item is already in cart
            cart_item = Cart.query.filter_by(user_id=current_user.uid, product_type=product_type, product_id=product_id).first()
            if cart_item:
                cart_item.quantity += quantity
                cart_item.price = price_to_use  # Update price in case promotion has changed
            else:
                new_cart_item = Cart(
                    user_id=current_user.uid,
                    product_type=product_type,
                    product_id=product_id,
                    quantity=quantity,
                    price=price_to_use,
                    date_added=datetime.utcnow()
                )
                db.session.add(new_cart_item)

            db.session.commit()

            return jsonify({'success': True, 'message': f'Added {quantity} x {product.type} to cart.'}), 200

        except Exception as e:
            print(f"Error adding to cart: {e}")
            db.session.rollback()
            return jsonify({'error': 'An error occurred while adding the item to the cart.'}), 500

    @app.route("/cart", methods=["GET"])
    @login_required
    def view_cart():
        from models import Cart  # Local import
        token = extract_auth_token(request)
        user_id = decode_token(token, app)
        cart_items = Cart.query.filter_by(user_id=current_user.uid).all()
        cart_details = []
        subtotal = 0

        for item in cart_items:
            product = item.get_product()
            if product:
                # Check for active promotion
                promotion = Promotion.query.filter_by(
                    product_type=item.product_type,
                    product_id=item.product_id,
                    active=True
                ).first()
                
                # Use promotional price if there's an active promotion
                if promotion and promotion.is_active():
                    price = promotion.discounted_price
                else:
                    price = product.price

                total_price = price * item.quantity
                subtotal += total_price
                
                cart_details.append({
                    'cart_id': item.id,
                    'product_id': item.product_id,
                    'product_type': item.product_type,
                    'name': product.type,
                    'price': price,  # Using the determined price (original or promotional)
                    'original_price': product.price,  # Optional: if you want to show the original price
                    'size': product.size if hasattr(product, 'size') else 'N/A',
                    'quantity': item.quantity,
                    'total_price': total_price,
                    'image': f"images/{item.product_type.lower()}/{product.type.replace(' ', '_').lower()}.jpg",
                    'has_promotion': bool(promotion and promotion.is_active())
                })

        return render_template('cart.html', cart=cart_details, subtotal=subtotal)


    @app.route("/cart/update", methods=["POST"])
    def update_cart():
        from models import Cart, Promotion  # Local import

        try:
            data = request.get_json()
            cart_id = data.get('cart_id')
            new_quantity = data.get('quantity')

            if not cart_id or not new_quantity:
                return jsonify({'error': 'Cart ID and new quantity are required.'}), 400

            try:
                new_quantity = int(new_quantity)
                if new_quantity < 1:
                    return jsonify({'error': 'Quantity must be at least 1.'}), 400
            except ValueError:
                return jsonify({'error': 'Invalid quantity value.'}), 400

            cart_item = Cart.query.filter_by(id=cart_id, user_id=current_user.uid).first()
            if not cart_item:
                return jsonify({'error': 'Cart item not found.'}), 404

            product = cart_item.get_product()
            if not product:
                return jsonify({'error': 'Associated product not found.'}), 404

            if new_quantity > product.quantity:
                return jsonify({'error': 'Requested quantity exceeds available stock.'}), 400

            cart_item.quantity = new_quantity

            # Check for active promotion
            promotion = Promotion.query.filter_by(
                product_type=cart_item.product_type,
                product_id=cart_item.product_id,
                active=True
            ).first()
            
            # Use promotional price if there's an active promotion
            if promotion and promotion.is_active():
                price = promotion.discounted_price
            else:
                price = product.price

            db.session.commit()

            total_price = price * cart_item.quantity

            # Calculate new subtotal with promotions
            subtotal = 0
            cart_items = Cart.query.filter_by(user_id=current_user.uid).all()
            for item in cart_items:
                item_product = item.get_product()
                if item_product:
                    # Check for promotion for each item
                    item_promotion = Promotion.query.filter_by(
                        product_type=item.product_type,
                        product_id=item.product_id,
                        active=True
                    ).first()
                    
                    if item_promotion and item_promotion.is_active():
                        item_price = item_promotion.discounted_price
                    else:
                        item_price = item_product.price
                        
                    subtotal += item_price * item.quantity

            return jsonify({
                'message': 'Cart updated successfully.',
                'total_price': total_price,
                'subtotal': subtotal
            }), 200

        except Exception as e:
            print(f"Error updating cart: {e}")
            return jsonify({'error': 'An error occurred while updating the cart.'}), 500

    @app.route("/cart/remove", methods=["POST"])
    def remove_from_cart():

        try:
            data = request.get_json()
            cart_id = data.get('cart_id')

            if not cart_id:
                return jsonify({'error': 'Cart ID is required.'}), 400

            cart_item = Cart.query.filter_by(id=cart_id, user_id=current_user.uid).first()
            if not cart_item:
                return jsonify({'error': 'Cart item not found.'}), 404

            db.session.delete(cart_item)
            db.session.commit()

            cart_items = Cart.query.filter_by(user_id=current_user.uid).all()
            subtotal = sum(
                [item.get_product().price * item.quantity for item in cart_items if item.get_product()]
            )

            return jsonify({'message': 'Item removed from cart.', 'subtotal': subtotal}), 200

        except Exception as e:
            print(f"Error removing from cart: {e}")
            return jsonify({'error': 'An error occurred while removing the item from the cart.'}), 500

    # Checkout Routes


    @app.route("/checkout", methods=["GET", "POST"])
    def checkout():
        cart_items = Cart.query.filter_by(user_id=current_user.uid).all()
        if not cart_items:
            flash('Your cart is empty.', 'info')
            return redirect(url_for('men'))

        cart_details = []
        subtotal = 0

        for item in cart_items:
            product = item.get_product()
            if product:
                total_price = product.price * item.quantity
                subtotal += total_price
                cart_details.append({
                    'cart_id': item.id,
                    'product_id': item.product_id,
                    'product_type': item.product_type,
                    'name': product.type,
                    'price': product.price,
                    'size': product.size if hasattr(product, 'size') else 'N/A',
                    'quantity': item.quantity,
                    'total_price': total_price,
                    'image': f"images/{item.product_type.lower()}/{product.type.replace(' ', '_').lower()}.jpg"
                })

        if request.method == 'POST':
            try:
                # Retrieve payment details from form
                card_number = request.form.get('card_number')
                expiration_date = request.form.get('expiration_date')
                cvv = request.form.get('cvv')
                cardholder_name = request.form.get('cardholder_name')

                # Simulate payment processing
                if not all([card_number, expiration_date, cvv, cardholder_name]):
                    flash('All payment fields are required.', 'danger')
                    return render_template('checkout.html', cart=cart_details, subtotal=subtotal)

                # Assume payment is successful

                # Create Invoice records and update stock
                for item in cart_items:
                    product = item.get_product()
                    if not product:
                        continue  # Skip if product not found

                    # Check stock
                    if item.quantity > product.quantity:
                        flash(f'Not enough stock for {product.type}.', 'danger')
                        return redirect(url_for('view_cart'))

                    # Deduct stock
                    product.quantity -= item.quantity

                    # Calculate total price
                    total_price = product.price * item.quantity

                    # Create Invoice
                    invoice = Invoice(
                        user_id=current_user.uid,
                        product_id=item.product_id,
                        product_type=item.product_type,
                        quantity=item.quantity,
                        price=product.price,
                        total_price=total_price,  # Populate total_price
                        status='Shipped'  # Assuming payment is done
                    )
                    db.session.add(invoice)

                    # Remove item from cart
                    db.session.delete(item)

                db.session.commit()
                flash('Checkout successful! Your order has been placed.', 'success')
                return redirect(url_for('index'))

            except Exception as e:
                print(f"Error during checkout: {e}")
                db.session.rollback()
                flash('An error occurred during checkout. Please try again.', 'danger')
                return redirect(url_for('view_cart'))

        return render_template('checkout.html', cart=cart_details, subtotal=subtotal)



        
        
        # @app.route('/', methods =['GET', 'POST'])
        # def index():
        #     if request.method == 'GET':
        #         people = Person.query.all()
        #         return render_template('index.html', people=people)
        #     elif request.method =='POST':
        #         name = request.form.get('name')
        #         age = int(request.form.get('age'))
        #         job = request.form.get('job')
        #         person = Person(name=name, age=age, job=job) # here we are creating the new person that we want to add to our database
        #         db.session.add(person)
        #         db.session.commit()
        #         people = Person.query.all()
        #         return render_template('index.html', people=people)
        
        # @app.route('/delete/<pid>', methods=['DELETE'])
        # def delete(pid):
        #     Person.query.filter(Person.pid==pid).delete()
        #     db.session.commit()
        #     people = Person.query.all()
        #     return render_template('index.html', people=people)
        
        # @app.route('/details/<int:pid>')
        # def details(pid):
        #     person = Person.query.filter(Person.pid==pid).first()
        #     return render_template('detail.html', person= person)