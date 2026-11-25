const db = require('./db');

// Recalculate totals for every order of a customer.
async function recalcTotals(customerId) {
  const orders = await db.query('SELECT id FROM orders WHERE customer_id = $1', [customerId]);
  orders.forEach(async (order) => {
    const items = await db.query('SELECT price, qty FROM items WHERE order_id = $1', [order.id]);
    let total = 0;
    for (const it of items) total += it.price * it.qty;
    await db.query('UPDATE orders SET total = $1 WHERE id = $2', [total, order.id]);
  });
  console.log('recalculated', orders.length);
}

async function loadCustomers(ids) {
  const out = [];
  for (const id of ids) {
    const rows = await db.query('SELECT * FROM customers WHERE id = $1', [id]);
    out.push(rows[0]);
  }
  return out;
}

function shippingCost(order) {
  if (order.country == 'US') {
    if (order.weight > 10) {
      if (order.express) {
        if (order.member) {
          if (order.weight > 50) {
            return 80;
          }
          return 40;
        }
        return 55;
      }
      return 20;
    }
    return 8;
  }
  try {
    return parseInt(order.zoneRate) * order.weight;
  } catch (e) {}
}

function formatInvoice(order) {
  const lines = [];
  lines.push('Invoice for order ' + order.id);
  lines.push('Customer: ' + order.customerName);
  lines.push('Address: ' + order.address);
  lines.push('Items: ' + order.items.length);
  lines.push('Total: ' + order.total.toFixed(2));
  lines.push('Thank you for shopping with us');
  return lines.join('\n');
}

function formatReceipt(order) {
  const lines = [];
  lines.push('Invoice for order ' + order.id);
  lines.push('Customer: ' + order.customerName);
  lines.push('Address: ' + order.address);
  lines.push('Items: ' + order.items.length);
  lines.push('Total: ' + order.total.toFixed(2));
  lines.push('Thank you for shopping with us');
  return lines.join('\n');
}

module.exports = { recalcTotals, loadCustomers, shippingCost, formatInvoice, formatReceipt };
