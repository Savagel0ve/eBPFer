import json
import sqlite3

# 加载 JSON 文件
with open("file.json", "r", encoding="utf-8") as f:
    policy = json.load(f)

# 连接 SQLite 数据库（或创建）
conn = sqlite3.connect("policy.db")
cursor = conn.cursor()

# 创建表
cursor.execute("""
CREATE TABLE IF NOT EXISTS file_policy (
    rule_id TEXT PRIMARY KEY,
    strategy_name TEXT,
    allowed_processes TEXT,
    programs TEXT,
    application_scenarios TEXT,
    active_name TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS file_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT,
    file_path TEXT,
    disallowed_operations TEXT,
    FOREIGN KEY(rule_id) REFERENCES file_policy(rule_id)
)
""")



def upsert_policy(policy: dict):
    conn = sqlite3.connect("policy.db")
    cursor = conn.cursor()

    # 查询 rule_id 是否存在
    cursor.execute("SELECT 1 FROM file_policy WHERE rule_id = ?", (policy["rule_id"],))
    exists = cursor.fetchone()
    rule_id = policy["rule_id"]

    if exists:
        # 更新已有记录
        cursor.execute("""
            UPDATE file_policy SET
                strategy_name = ?,
                allowed_processes = ?,
                programs = ?,
                application_scenarios = ?,
                active_name = ?
            WHERE rule_id = ?
        """, (
            policy["strategy_name"],
            policy["allowed_processes"],
            policy["programs"],
            policy["application_scenarios"],
            policy["activeName"],
            policy["rule_id"]
        ))
        print(f"已更新策略 rule_id={policy['rule_id']}")
    else:
        # 插入新记录
        cursor.execute("""
            INSERT INTO file_policy (
                rule_id, strategy_name, allowed_processes, programs,
                application_scenarios, active_name
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            policy["rule_id"],
            policy["strategy_name"],
            policy["allowed_processes"],
            policy["programs"],
            policy["application_scenarios"],
            policy["activeName"]
        ))
        print(f"已插入新策略 rule_id={policy['rule_id']}")

    cursor.execute("DELETE FROM file_rules WHERE rule_id = ?", (rule_id,))
    print(f"[file_rules] 删除旧规则 rule_id={rule_id}")

    # 插入 file_rules 中的新规则
    for file_entry in policy.get("file_name", []):
        file_path = file_entry["file_path"]
        disallowed_ops = ",".join(file_entry["disallowed_operations"])
        cursor.execute("""
            INSERT INTO file_rules (rule_id, file_path, disallowed_operations)
            VALUES (?, ?, ?)
        """, (rule_id, file_path, disallowed_ops))
    print(f"[file_rules] 插入新规则 count={len(policy.get('file_name', []))}")
        

    conn.commit()
    conn.close()



upsert_policy(policy)
# 提交并关闭
conn.commit()
conn.close()
print("策略已成功导入数据库。")
