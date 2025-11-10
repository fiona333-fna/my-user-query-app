import pymysql
from flask import Flask, request, jsonify, session
from dbutils.pooled_db import PooledDB
#from flask_cors import CORS
from pymysql.cursors import DictCursor
import os

app = Flask(__name__)
#启动CORES允许所有来源
#CORS(app)

DB_HOST = os.environ.get('DB_HOST')
DB_USER = os.environ.get('DB_USER')
DB_PASS = os.environ.get('DB_PASS')
DB_NAME = os.environ.get('DB_NAME', 'user_service_db')

POOL = PooledDB(
    creator=pymysql,
    maxconnections=10,
    mincached=2,
    maxcached=5,
    blocking=True,
    setsession=[],
    ping=0,
    host=DB_HOST,
    port=3306,
    user=DB_USER,
    passwd=DB_PASS,
    db=DB_NAME
)

def fetchOne(sql,parmas):

    conn = POOL.connection()
    cursor = conn.cursor(DictCursor)

    #cursor.execute("select * from users where user_id=%s ", (userid))
    cursor.execute(sql,parmas)
    result = cursor.fetchone()

    cursor.close()
    conn.close()
    return result

@app.route('/', methods=['GET'])
def health_check():
    return "Backend Status: Healthy", 200

@app.route('/getinfo',methods=['POST'])
def getinfo():
    # Check Userid
    #userid = request.args.get("userid")
    userid = request.get_json().get("userid")

    if not userid:
        return jsonify({"status": False, 'error': "userid is empty"})

    result = fetchOne("select * from users where user_id=%s ", (userid))
    if not result:
        return jsonify({"status": False, 'error':"没有这个用户"})
    if result.get('creation_date'):
        result['creation_date'] = result['creation_date'].strftime('%Y-%m-%d %H:%M:%S')

    return jsonify({"status": True, 'data': result})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)