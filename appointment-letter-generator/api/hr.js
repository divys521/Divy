import { neon } from '@neondatabase/serverless';
import { createHmac, timingSafeEqual } from 'node:crypto';

const COOKIE = 'ess_hr_session';
const SESSION_SECONDS = 8 * 60 * 60;

function sign(expiry) {
  return createHmac('sha256', process.env.SESSION_SECRET).update(String(expiry)).digest('base64url');
}
function cookieValue(req) {
  const raw = req.headers.cookie || '';
  const part = raw.split(';').map(x => x.trim()).find(x => x.startsWith(COOKIE + '='));
  return part ? decodeURIComponent(part.slice(COOKIE.length + 1)) : '';
}
function isAuthenticated(req) {
  const secret = process.env.SESSION_SECRET;
  if (!secret) return false;
  const [expiry, signature, extra] = cookieValue(req).split('.');
  if (!expiry || !signature || extra || !/^\d+$/.test(expiry) || Number(expiry) < Math.floor(Date.now() / 1000)) return false;
  const expected = Buffer.from(sign(expiry));
  const actual = Buffer.from(signature);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
function setCookie(req, res, value, maxAge) {
  const secure = req.headers['x-forwarded-proto'] === 'https' || String(req.headers.host || '').endsWith('.vercel.app');
  res.setHeader('Set-Cookie', COOKIE + '=' + encodeURIComponent(value) + '; Path=/api/hr; HttpOnly; SameSite=Strict; Max-Age=' + maxAge + (secure ? '; Secure' : ''));
}
function send(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(payload));
}
function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
function cleanText(v) { return v == null ? '' : String(v); }
function number(v) { const n = Number(v ?? 0); if (!Number.isFinite(n) || n < 0) throw new Error('Invalid numeric value in employee details.'); return n; }

export default async function handler(req, res) {
  const action = String(req.query?.action || '');
  if (req.method === 'OPTIONS') { res.statusCode = 204; return res.end(); }
  if (action === 'login') {
    if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed.' });
    if (!process.env.HR_APP_PASSWORD || !process.env.SESSION_SECRET) return send(res, 503, { error: 'HR access has not been configured yet. Please ask the Vercel project administrator to set HR_APP_PASSWORD and SESSION_SECRET.' });
    const password = req.body?.password;
    if (typeof password !== 'string' || !safeEqual(password, process.env.HR_APP_PASSWORD)) return send(res, 401, { error: 'Incorrect HR access password.' });
    const expiry = String(Math.floor(Date.now() / 1000) + SESSION_SECONDS);
    setCookie(req, res, expiry + '.' + sign(expiry), SESSION_SECONDS);
    return send(res, 200, { ok: true });
  }
  if (action === 'logout') {
    setCookie(req, res, '', 0);
    return send(res, 200, { ok: true });
  }
  if (action === 'me') {
    if (!isAuthenticated(req)) return send(res, 401, { error: 'Please sign in.' });
    return send(res, 200, { ok: true });
  }
  if (!isAuthenticated(req)) return send(res, 401, { error: 'Your HR session has expired. Please sign in again.' });
  if (!process.env.DATABASE_URL) return send(res, 503, { error: 'The HR database is not configured on the server.' });
  const sql = neon(process.env.DATABASE_URL);
  try {
    if (action === 'next-number') {
      if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed.' });
      const letterDate = req.body?.letter_date;
      if (typeof letterDate !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(letterDate)) return send(res, 400, { error: 'A valid letter date is required.' });
      const rows = await sql.query('SELECT ess_hr.next_appointment_letter_number($1::date) AS number', [letterDate]);
      return send(res, 200, { number: rows[0]?.number });
    }
    if (action === 'list') {
      if (req.method !== 'GET') return send(res, 405, { error: 'Method not allowed.' });
      const rows = await sql.query(`SELECT al.id, al.letter_number, al.status, al.generated_at,
        jsonb_build_object('employee_name', er.employee_name, 'employee_id', er.employee_id,
          'designation', er.designation, 'date_of_joining', er.date_of_joining, 'letter_date', er.letter_date) AS employee_records,
        CASE WHEN gd.id IS NULL THEN NULL ELSE jsonb_build_object('storage_path', gd.storage_path, 'file_name', gd.file_name) END AS generated_documents
        FROM ess_hr.appointment_letters al
        JOIN ess_hr.employee_records er ON er.id = al.employee_record_id
        LEFT JOIN ess_hr.generated_documents gd ON gd.appointment_letter_id = al.id
        ORDER BY al.generated_at DESC LIMIT 1000`);
      return send(res, 200, { data: rows });
    }
    if (action === 'pdf') {
      if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed.' });
      const id = req.body?.appointment_letter_id;
      if (typeof id !== 'string' || !/^[0-9a-f-]{36}$/i.test(id)) return send(res, 400, { error: 'A valid appointment letter ID is required.' });
      const rows = await sql.query('SELECT pdf_base64, file_name FROM ess_hr.generated_documents WHERE appointment_letter_id = $1::uuid LIMIT 1', [id]);
      if (!rows.length || !rows[0].pdf_base64) return send(res, 404, { error: 'PDF data was not found in Neon.' });
      return send(res, 200, { data: rows[0] });
    }
    if (action === 'save') {
      if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed.' });
      const b = req.body || {};
      const e = b.employee || {};
      if (!cleanText(e.employee_name).trim() || !cleanText(e.employee_id).trim() || !cleanText(e.designation).trim()) return send(res, 400, { error: 'Employee name, employee ID and designation are required.' });
      if (!/^\d{4}-\d{2}-\d{2}$/.test(cleanText(e.date_of_joining)) || !/^\d{4}-\d{2}-\d{2}$/.test(cleanText(e.letter_date))) return send(res, 400, { error: 'Valid joining and letter dates are required.' });
      if (typeof b.letter_number !== 'string' || !/^ESS\/HR\/APP\/\d{4}\/\d{2}\/\d{3,}$/.test(b.letter_number)) return send(res, 400, { error: 'Invalid appointment letter number.' });
      if (typeof b.file_name !== 'string' || !/^[a-zA-Z0-9._-]{1,180}\.pdf$/i.test(b.file_name)) return send(res, 400, { error: 'Invalid PDF file name.' });
      if (typeof b.pdf_base64 !== 'string' || b.pdf_base64.length < 100 || b.pdf_base64.length > 12000000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(b.pdf_base64)) return send(res, 400, { error: 'The PDF data is missing or too large.' });
      const vals = [
        cleanText(e.employee_name).trim(), cleanText(e.employee_id).trim(), cleanText(e.address),
        cleanText(e.contact_number), cleanText(e.designation).trim(), e.date_of_joining, e.letter_date,
        cleanText(e.probation_period), cleanText(e.contract_period), number(e.contract_amount),
        number(e.basic), number(e.hra), number(e.pf), number(e.gratuity), number(e.earned_leave),
        number(e.accidental_insurance), number(e.gross), number(e.total_benefits), number(e.ctc),
        b.letter_number, 'neon-db/' + b.file_name, b.file_name, b.pdf_base64
      ];
      const rows = await sql.query(`WITH employee AS (
        INSERT INTO ess_hr.employee_records
          (employee_name, employee_id, address, contact_number, designation, date_of_joining, letter_date,
           probation_period, contract_period, contract_amount, basic, hra, pf, gratuity, earned_leave,
           accidental_insurance, gross, total_benefits, ctc)
        VALUES ($1,$2,$3,$4,$5,$6::date,$7::date,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
        RETURNING id
      ), letter AS (
        INSERT INTO ess_hr.appointment_letters (employee_record_id, letter_number, status, generated_at)
        SELECT employee.id, $20, 'Generated', now() FROM employee
        RETURNING id
      ), document AS (
        INSERT INTO ess_hr.generated_documents (appointment_letter_id, storage_path, file_name, mime_type, pdf_base64)
        SELECT letter.id, $21, $22, 'application/pdf', $23 FROM letter
        RETURNING id
      )
      SELECT letter.id AS appointment_letter_id FROM letter CROSS JOIN document`, vals);
      return send(res, 200, { ok: true, appointment_letter_id: rows[0]?.appointment_letter_id });
    }
    return send(res, 404, { error: 'Unknown HR API action.' });
  } catch (error) {
    console.error('Protected HR API operation failed:', action, error?.message || 'unknown error');
    return send(res, 500, { error: 'The HR database operation failed. Check server logs for details.' });
  }
}
