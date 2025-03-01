with open("app.py", "r", encoding="utf-8") as f:
    content = f.read()

clean_content = content.replace("\u00A0", " ")

with open("app.py", "w", encoding="utf-8") as f:
    f.write(clean_content)

print("Non-breaking spaces removed successfully!")
