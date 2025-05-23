from flask import Blueprint, request, jsonify
from app.models.listing import Listing
from app.models.comment import Comment
from app.extensions import db
from app.auth_utils import token_required
from datetime import datetime

bp = Blueprint("listings", __name__)

# Create a new listing
@bp.route("/listings", methods=["POST"])
@token_required
def create_listing(current_user):
    """Create a new listing"""
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['title', 'price']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400
    
    new_listing = Listing(
        title=data['title'],
        description=data.get('description'),
        price=float(data['price']),  # Convert to float
        location=data.get('location'),
        image_url=data.get('image_url'),
        created_by=current_user.id
    )
    
    try:
        db.session.add(new_listing)
        db.session.commit()
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    
    return jsonify({
        'id': new_listing.id,
        'title': new_listing.title,
        'description': new_listing.description,
        'price': new_listing.price,
        'location': new_listing.location,
        'image_url': new_listing.image_url,
        'created_by': new_listing.created_by,
        'created_at': new_listing.created_at.isoformat(),
        'updated_at': new_listing.updated_at.isoformat(),
        'status': new_listing.status
    }), 201

@bp.route("/listings", methods=["GET"])
def get_listings():
    """Get all active listings"""
    # Add query parameters for filtering
    status = request.args.get('status', 'active')
    
    listings = Listing.query.filter_by(status=status).all()
    return jsonify([{
        'id': listing.id,
        'title': listing.title,
        'description': listing.description,
        'price': listing.price,
        'location': listing.location,
        'image_url': listing.image_url,
        'created_by': listing.created_by,
        'created_at': listing.created_at.isoformat(),
        'updated_at': listing.updated_at.isoformat(),
        'status': listing.status,
        'comment_count': len(listing.comments) if listing.comments else 0
    } for listing in listings])

@bp.route("/listings/<int:listing_id>", methods=["GET"])
def get_listing(listing_id):
    """Get a specific listing"""
    listing = Listing.query.get_or_404(listing_id)
    return jsonify({
        'id': listing.id,
        'title': listing.title,
        'description': listing.description,
        'price': listing.price,
        'location': listing.location,
        'image_url': listing.image_url,
        'created_by': listing.created_by,
        'created_at': listing.created_at.isoformat(),
        'updated_at': listing.updated_at.isoformat(),
        'status': listing.status,
        'comment_count': len(listing.comments) if listing.comments else 0
    })

@bp.route("/listings/<int:listing_id>", methods=["PUT"])
@token_required
def update_listing(current_user, listing_id):
    """Update a specific listing"""
    listing = Listing.query.get_or_404(listing_id)
    
    # Check if user owns the listing or is admin
    if listing.created_by != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized to modify this listing'}), 403
    
    data = request.get_json()
    
    # Update fields if provided
    if 'title' in data:
        listing.title = data['title']
    if 'description' in data:
        listing.description = data['description']
    if 'price' in data:
        try:
            listing.price = float(data['price'])
        except ValueError:
            return jsonify({'error': 'Invalid price format'}), 400
    if 'location' in data:
        listing.location = data['location']
    if 'image_url' in data:
        listing.image_url = data['image_url']
    if 'status' in data and data['status'] in ['active', 'sold', 'deleted']:
        listing.status = data['status']
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400
    
    return jsonify({
        'id': listing.id,
        'title': listing.title,
        'description': listing.description,
        'price': listing.price,
        'location': listing.location,
        'image_url': listing.image_url,
        'created_by': listing.created_by,
        'created_at': listing.created_at.isoformat(),
        'updated_at': listing.updated_at.isoformat(),
        'status': listing.status
    })

@bp.route("/listings/<int:listing_id>", methods=["DELETE"])
@token_required
def delete_listing(current_user, listing_id):
    """Delete a specific listing"""
    listing = Listing.query.get_or_404(listing_id)
    
    # Check if user owns the listing or is admin
    if listing.created_by != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized to delete this listing'}), 403
    
    # Soft delete - just update status to deleted
    listing.status = 'deleted'
    db.session.commit()
    
    return '', 204

@bp.route("/listings/<int:listing_id>/comments", methods=["GET"])
def get_listing_comments(listing_id):
    """Get all comments for a specific listing"""
    listing = Listing.query.get_or_404(listing_id)
    comments = Comment.query.filter_by(listing_id=listing_id).all()
    
    return jsonify([{
        'id': comment.id,
        'content': comment.content,
        'created_by': comment.created_by,
        'created_at': comment.created_at.isoformat(),
        'updated_at': comment.updated_at.isoformat(),
        'author': {
            'id': comment.user_author.id,
            'fullname': comment.user_author.fullname
        } if comment.user_author else None
    } for comment in comments])

@bp.route("/listings/<int:listing_id>/comments", methods=["POST"])
@token_required
def add_comment(current_user, listing_id):
    """Add a new comment to a listing"""
    listing = Listing.query.get_or_404(listing_id)
    data = request.get_json()
    
    if not data or 'content' not in data or not data['content'].strip():
        return jsonify({'error': 'Comment content is required'}), 400
    
    new_comment = Comment(
        content=data['content'].strip(),
        listing_id=listing_id,
        created_by=current_user.id
    )
    
    db.session.add(new_comment)
    db.session.commit()
    
    return jsonify({
        'id': new_comment.id,
        'content': new_comment.content,
        'created_by': new_comment.created_by,
        'created_at': new_comment.created_at.isoformat(),
        'updated_at': new_comment.updated_at.isoformat(),
        'author': {
            'id': new_comment.user_author.id,
            'fullname': new_comment.user_author.fullname
        } if new_comment.user_author else None
    }), 201

# Optional: Edit and Delete routes
@bp.route("/listings/<int:listing_id>/comments/<int:comment_id>", methods=["PUT"])
@token_required
def update_comment(current_user, listing_id, comment_id):
    """Update a specific comment"""
    comment = Comment.query.get_or_404(comment_id)
    
    # Verify the comment belongs to the specified listing
    if comment.listing_id != listing_id:
        return jsonify({'error': 'Comment does not belong to this listing'}), 404
    
    # Check if user owns the comment or is admin
    if comment.created_by != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized to modify this comment'}), 403
    
    data = request.get_json()
    
    if 'content' in data:
        comment.content = data['content']
    
    db.session.commit()
    
    return jsonify({
        'id': comment.id,
        'content': comment.content,
        'created_by': comment.created_by,
        'created_at': comment.created_at.isoformat(),
        'updated_at': comment.updated_at.isoformat(),
        'author': {
            'id': comment.user_author.id,
            'fullname': comment.user_author.fullname
        } if comment.user_author else None
    })

@bp.route("/listings/<int:listing_id>/comments/<int:comment_id>", methods=["DELETE"])
@token_required
def delete_comment(current_user, listing_id, comment_id):
    """Delete a specific comment"""
    comment = Comment.query.get_or_404(comment_id)
    
    # Verify the comment belongs to the specified listing
    if comment.listing_id != listing_id:
        return jsonify({'error': 'Comment does not belong to this listing'}), 404
    
    # Check if user owns the comment or is admin
    if comment.created_by != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized to delete this comment'}), 403
    
    db.session.delete(comment)
    db.session.commit()
    
    return '', 204 