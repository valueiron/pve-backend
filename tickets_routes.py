"""
tickets_routes.py — Flask Blueprint proxying requests to the tickets-api service.

Prefix: /api/tickets
"""

from flask import Blueprint

import config
from proxy import proxy_request

tickets_bp = Blueprint('tickets', __name__)

_SVC = 'tickets-api'


def _p(path, method='GET'):
    return proxy_request(config.TICKETS_API_URL, path, _SVC, method)


# ── Boards ─────────────────────────────────────────────────────────────────────

@tickets_bp.get('/api/tickets/boards')
def tickets_list_boards():
    return _p('boards')


@tickets_bp.post('/api/tickets/boards')
def tickets_create_board():
    return _p('boards', 'POST')


@tickets_bp.get('/api/tickets/boards/<int:board_id>')
def tickets_get_board(board_id):
    return _p(f'boards/{board_id}')


@tickets_bp.put('/api/tickets/boards/<int:board_id>')
def tickets_update_board(board_id):
    return _p(f'boards/{board_id}', 'PUT')


@tickets_bp.delete('/api/tickets/boards/<int:board_id>')
def tickets_delete_board(board_id):
    return _p(f'boards/{board_id}', 'DELETE')


# ── Columns ────────────────────────────────────────────────────────────────────

@tickets_bp.get('/api/tickets/boards/<int:board_id>/columns')
def tickets_list_columns(board_id):
    return _p(f'boards/{board_id}/columns')


@tickets_bp.post('/api/tickets/boards/<int:board_id>/columns')
def tickets_create_column(board_id):
    return _p(f'boards/{board_id}/columns', 'POST')


@tickets_bp.put('/api/tickets/boards/<int:board_id>/columns/reorder')
def tickets_reorder_columns(board_id):
    return _p(f'boards/{board_id}/columns/reorder', 'PUT')


@tickets_bp.put('/api/tickets/boards/<int:board_id>/columns/<int:col_id>')
def tickets_update_column(board_id, col_id):
    return _p(f'boards/{board_id}/columns/{col_id}', 'PUT')


@tickets_bp.delete('/api/tickets/boards/<int:board_id>/columns/<int:col_id>')
def tickets_delete_column(board_id, col_id):
    return _p(f'boards/{board_id}/columns/{col_id}', 'DELETE')


# ── Tickets ────────────────────────────────────────────────────────────────────

@tickets_bp.get('/api/tickets/boards/<int:board_id>/tickets')
def tickets_list_tickets(board_id):
    return _p(f'boards/{board_id}/tickets')


@tickets_bp.post('/api/tickets/boards/<int:board_id>/tickets')
def tickets_create_ticket(board_id):
    return _p(f'boards/{board_id}/tickets', 'POST')


@tickets_bp.get('/api/tickets/boards/<int:board_id>/tickets/<int:tick_id>')
def tickets_get_ticket(board_id, tick_id):
    return _p(f'boards/{board_id}/tickets/{tick_id}')


@tickets_bp.put('/api/tickets/boards/<int:board_id>/tickets/<int:tick_id>')
def tickets_update_ticket(board_id, tick_id):
    return _p(f'boards/{board_id}/tickets/{tick_id}', 'PUT')


@tickets_bp.delete('/api/tickets/boards/<int:board_id>/tickets/<int:tick_id>')
def tickets_delete_ticket(board_id, tick_id):
    return _p(f'boards/{board_id}/tickets/{tick_id}', 'DELETE')


@tickets_bp.put('/api/tickets/boards/<int:board_id>/tickets/<int:tick_id>/move')
def tickets_move_ticket(board_id, tick_id):
    return _p(f'boards/{board_id}/tickets/{tick_id}/move', 'PUT')
