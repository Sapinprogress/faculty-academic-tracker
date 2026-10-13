
import sqlite3
import hashlib
import secrets
from pathlib import Path
from contextlib import contextmanager
from datetime import date

import pandas as pd
import plotly.express as px
import streamlit as st


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="Faculty Academic Tracker",
    page_icon="📚",
    layout="wide",
    initial_sidebar_state="expanded",
)

DB_PATH = Path(__file__).parent / "faculty_tracker.db"

st.markdown(
    """
    <style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 700;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        color: #777;
        margin-bottom: 1.5rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# DATABASE CONNECTION
# =========================================================

@contextmanager
def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# =========================================================
# PASSWORD SECURITY
# =========================================================

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        200000,
    ).hex()

    return password_hash, salt


def verify_password(password, stored_hash, salt):
    calculated_hash, _ = hash_password(password, salt)

    return secrets.compare_digest(
        calculated_hash,
        stored_hash,
    )


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def initialize_database():
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS faculty (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                roll_no TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                department TEXT NOT NULL,
                semester INTEGER NOT NULL,
                attendance_present INTEGER DEFAULT 0,
                total_classes INTEGER DEFAULT 0,
                internal_marks REAL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                task_type TEXT NOT NULL,
                due_date TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                task_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending',
                UNIQUE(student_id, task_id),
                FOREIGN KEY(student_id) REFERENCES students(id)
                    ON DELETE CASCADE,
                FOREIGN KEY(task_id) REFERENCES tasks(id)
                    ON DELETE CASCADE
            );
            """
        )

        student_count = conn.execute(
            "SELECT COUNT(*) AS total FROM students"
        ).fetchone()["total"]

        if student_count == 0:
            sample_students = [
                ("CE001", "Aarav Patel", "Computer Engineering", 5, 18, 20, 82),
                ("CE002", "Diya Shah", "Computer Engineering", 5, 15, 20, 76),
                ("CE003", "Rohan Mehta", "Computer Engineering", 5, 12, 20, 61),
                ("CE004", "Anaya Desai", "Computer Engineering", 5, 19, 20, 91),
                ("CE005", "Krish Joshi", "Computer Engineering", 5, 10, 20, 48),
                ("CE006", "Mira Trivedi", "Computer Engineering", 5, 17, 20, 85),
                ("CE007", "Vivaan Shah", "Computer Engineering", 5, 14, 20, 69),
                ("CE008", "Isha Patel", "Computer Engineering", 5, 20, 20, 94),
            ]

            conn.executemany(
                """
                INSERT INTO students
                (roll_no, name, department, semester,
                 attendance_present, total_classes, internal_marks)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                sample_students,
            )

        task_count = conn.execute(
            "SELECT COUNT(*) AS total FROM tasks"
        ).fetchone()["total"]

        if task_count == 0:
            sample_tasks = [
                ("Python Assignment 1", "Assignment", str(date.today())),
                ("System Software Practical", "Practical", str(date.today())),
                ("PDS Mini Project", "Project", str(date.today())),
            ]

            conn.executemany(
                """
                INSERT INTO tasks (title, task_type, due_date)
                VALUES (?, ?, ?)
                """,
                sample_tasks,
            )

        submission_count = conn.execute(
            "SELECT COUNT(*) AS total FROM submissions"
        ).fetchone()["total"]

        if submission_count == 0:
            students = conn.execute(
                "SELECT id FROM students"
            ).fetchall()

            tasks = conn.execute(
                "SELECT id FROM tasks"
            ).fetchall()

            for student_index, student in enumerate(students):
                for task_index, task in enumerate(tasks):
                    if (student_index + task_index) % 3 == 0:
                        status = "Submitted"
                    elif (student_index + task_index) % 3 == 1:
                        status = "Pending"
                    else:
                        status = "Late"

                    conn.execute(
                        """
                        INSERT OR IGNORE INTO submissions
                        (student_id, task_id, status)
                        VALUES (?, ?, ?)
                        """,
                        (student["id"], task["id"], status),
                    )


# =========================================================
# FACULTY REGISTRATION AND AUTHENTICATION
# =========================================================

def register_faculty(full_name, username, password):
    full_name = full_name.strip()
    username = username.strip().lower()

    if not full_name or not username or not password:
        return False, "Please fill in every field."

    if len(username) < 3:
        return False, "Username must contain at least 3 characters."

    if len(password) < 8:
        return False, "Password must contain at least 8 characters."

    if len(full_name) > 100 or len(username) > 50:
        return False, "Name or username is too long."

    password_hash, salt = hash_password(password)

    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO faculty
                (full_name, username, password_hash, password_salt)
                VALUES (?, ?, ?, ?)
                """,
                (full_name, username, password_hash, salt),
            )

        return True, "Account created successfully! Please log in."

    except sqlite3.IntegrityError:
        return False, "This username already exists. Choose another."


def authenticate_faculty(username, password):
    username = username.strip().lower()

    with get_connection() as conn:
        faculty = conn.execute(
            """
            SELECT id, full_name, username, password_hash, password_salt
            FROM faculty
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

    if faculty is None:
        return None

    if verify_password(
        password,
        faculty["password_hash"],
        faculty["password_salt"],
    ):
        return {
            "id": faculty["id"],
            "full_name": faculty["full_name"],
            "username": faculty["username"],
        }

    return None


# =========================================================
# LOGIN AND REGISTRATION PAGE
# =========================================================

def login_page():
    st.markdown(
        "<h1 style='text-align:center;'>📚 Faculty Academic Tracker</h1>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<p style='text-align:center;'>"
        "Manage student records, attendance, assignments and marks"
        "</p>",
        unsafe_allow_html=True,
    )

    st.divider()

    left, center, right = st.columns([1, 1.3, 1])

    with center:
        login_tab, register_tab = st.tabs(
            ["🔐 Login", "📝 Faculty Registration"]
        )

        with login_tab:
            st.subheader("Faculty Login")

            with st.form("faculty_login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")

                login_button = st.form_submit_button(
                    "Login",
                    type="primary",
                    use_container_width=True,
                )

            if login_button:
                if not username.strip() or not password:
                    st.error("Enter your username and password.")
                else:
                    faculty = authenticate_faculty(username, password)

                    if faculty:
                        st.session_state["authenticated"] = True
                        st.session_state["faculty_id"] = faculty["id"]
                        st.session_state["username"] = faculty["username"]
                        st.session_state["full_name"] = faculty["full_name"]
                        st.rerun()
                    else:
                        st.error("Invalid username or password.")

        with register_tab:
            st.subheader("Create Faculty Account")

            with st.form("faculty_registration_form"):
                full_name = st.text_input("Full Name")
                new_username = st.text_input("Choose Username")
                new_password = st.text_input(
                    "Create Password",
                    type="password",
                )
                confirm_password = st.text_input(
                    "Confirm Password",
                    type="password",
                )

                register_button = st.form_submit_button(
                    "Register",
                    type="primary",
                    use_container_width=True,
                )

            if register_button:
                if new_password != confirm_password:
                    st.error("Passwords do not match.")
                else:
                    success, message = register_faculty(
                        full_name,
                        new_username,
                        new_password,
                    )

                    if success:
                        st.success(message)
                        st.info(
                            "Select the Login tab and use your new credentials."
                        )
                    else:
                        st.error(message)

            st.caption(
                "Use a unique username and a password of at least "
                "8 characters."
            )

    st.divider()
    st.caption(
        "Python • Streamlit • Pandas • Plotly • SQLite"
    )


# =========================================================
# DATA HELPERS
# =========================================================

def get_students():
    with get_connection() as conn:
        return pd.read_sql_query(
            "SELECT * FROM students ORDER BY roll_no",
            conn,
        )


def get_tasks():
    with get_connection() as conn:
        return pd.read_sql_query(
            "SELECT * FROM tasks ORDER BY due_date",
            conn,
        )


def get_submissions():
    with get_connection() as conn:
        return pd.read_sql_query(
            """
            SELECT
                submissions.id AS submission_id,
                students.id AS student_id,
                students.roll_no,
                students.name AS student_name,
                tasks.id AS task_id,
                tasks.title AS task_title,
                tasks.task_type,
                tasks.due_date,
                submissions.status
            FROM submissions
            JOIN students ON students.id = submissions.student_id
            JOIN tasks ON tasks.id = submissions.task_id
            ORDER BY tasks.due_date, students.roll_no
            """,
            conn,
        )


def calculate_attendance(present, total):
    if total <= 0:
        return 0.0

    return (present / total) * 100


def create_missing_submissions(task_id):
    with get_connection() as conn:
        students = conn.execute(
            "SELECT id FROM students"
        ).fetchall()

        for student in students:
            conn.execute(
                """
                INSERT OR IGNORE INTO submissions
                (student_id, task_id, status)
                VALUES (?, ?, 'Pending')
                """,
                (student["id"], task_id),
            )


# =========================================================
# DASHBOARD
# =========================================================

def dashboard_page():
    st.title("📊 Faculty Dashboard")
    st.write("Overview of student academic performance.")

    students = get_students()
    tasks = get_tasks()
    submissions = get_submissions()

    if students.empty:
        st.info("Add student records to view the dashboard.")
        return

    students["attendance_percentage"] = students.apply(
        lambda row: calculate_attendance(
            row["attendance_present"],
            row["total_classes"],
        ),
        axis=1,
    )

    total_students = len(students)
    average_attendance = students["attendance_percentage"].mean()
    average_marks = students["internal_marks"].mean()

    shortage_count = int(
        (students["attendance_percentage"] < 75).sum()
    )

    pending_count = (
        int((submissions["status"] == "Pending").sum())
        if not submissions.empty else 0
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Students", total_students)
    col2.metric("Average Attendance", f"{average_attendance:.1f}%")
    col3.metric("Average Internal Marks", f"{average_marks:.1f}")
    col4.metric("Pending Submissions", pending_count)

    st.divider()

    chart1, chart2 = st.columns(2)

    with chart1:
        st.subheader("Student Attendance")

        attendance_chart = px.bar(
            students,
            x="roll_no",
            y="attendance_percentage",
            color="attendance_percentage",
            hover_data=["name"],
            labels={
                "roll_no": "Roll Number",
                "attendance_percentage": "Attendance (%)",
            },
            title="Attendance Percentage by Student",
        )
        attendance_chart.add_hline(
            y=75,
            line_dash="dash",
            annotation_text="75% threshold",
        )
        attendance_chart.update_layout(
            xaxis_title="Roll Number",
            yaxis_range=[0, 100],
        )
        st.plotly_chart(attendance_chart, use_container_width=True)

    with chart2:
        st.subheader("Internal Marks")

        marks_chart = px.bar(
            students,
            x="roll_no",
            y="internal_marks",
            color="internal_marks",
            hover_data=["name"],
            labels={
                "roll_no": "Roll Number",
                "internal_marks": "Internal Marks",
            },
            title="Internal Marks by Student",
        )
        st.plotly_chart(marks_chart, use_container_width=True)

    st.subheader("⚠️ Students Requiring Attention")

    attention = students[
        (students["attendance_percentage"] < 75)
        | (students["internal_marks"] < 40)
    ].copy()

    if attention.empty:
        st.success("No students currently meet the attention criteria.")
    else:
        attention["Reason"] = attention.apply(
            lambda row: ", ".join(
                reason
                for condition, reason in [
                    (row["attendance_percentage"] < 75, "Low attendance"),
                    (row["internal_marks"] < 40, "Low internal marks"),
                ]
                if condition
            ),
            axis=1,
        )

        st.dataframe(
            attention[
                [
                    "roll_no",
                    "name",
                    "attendance_percentage",
                    "internal_marks",
                    "Reason",
                ]
            ].rename(
                columns={
                    "roll_no": "Roll Number",
                    "name": "Student Name",
                    "attendance_percentage": "Attendance (%)",
                    "internal_marks": "Internal Marks",
                }
            ),
            use_container_width=True,
            hide_index=True,
        )

    st.caption(f"Total assignments and practicals: {len(tasks)}")


# =========================================================
# STUDENT RECORDS
# =========================================================

def student_records_page():
    st.title("👨‍🎓 Student Records")
    st.write("Add, search and manage student information.")

    with st.expander("➕ Add New Student", expanded=False):
        with st.form("add_student_form"):
            col1, col2 = st.columns(2)

            with col1:
                roll_no = st.text_input("Roll Number")
                student_name = st.text_input("Student Name")
                department = st.text_input(
                    "Department",
                    value="Computer Engineering",
                )

            with col2:
                semester = st.number_input(
                    "Semester",
                    min_value=1,
                    max_value=8,
                    value=5,
                    step=1,
                )
                total_classes = st.number_input(
                    "Total Classes Held",
                    min_value=0,
                    value=0,
                    step=1,
                )
                attendance_present = st.number_input(
                    "Classes Attended",
                    min_value=0,
                    value=0,
                    step=1,
                )

            internal_marks = st.number_input(
                "Internal Marks (out of 100)",
                min_value=0.0,
                max_value=100.0,
                value=0.0,
                step=1.0,
            )

            add_button = st.form_submit_button(
                "Add Student",
                type="primary",
            )

        if add_button:
            roll_no = roll_no.strip().upper()
            student_name = student_name.strip()
            department = department.strip()

            if not roll_no or not student_name or not department:
                st.error("Please fill in all student details.")
            elif attendance_present > total_classes:
                st.error(
                    "Classes attended cannot exceed total classes held."
                )
            else:
                try:
                    with get_connection() as conn:
                        cursor = conn.execute(
                            """
                            INSERT INTO students
                            (roll_no, name, department, semester,
                             attendance_present, total_classes,
                             internal_marks)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                roll_no,
                                student_name,
                                department,
                                int(semester),
                                int(attendance_present),
                                int(total_classes),
                                float(internal_marks),
                            ),
                        )

                        new_student_id = cursor.lastrowid

                        existing_tasks = conn.execute(
                            "SELECT id FROM tasks"
                        ).fetchall()

                        for task in existing_tasks:
                            conn.execute(
                                """
                                INSERT OR IGNORE INTO submissions
                                (student_id, task_id, status)
                                VALUES (?, ?, 'Pending')
                                """,
                                (new_student_id, task["id"]),
                            )

                    st.success("Student added successfully.")
                    st.rerun()

                except sqlite3.IntegrityError:
                    st.error("This roll number already exists.")

    st.subheader("Search Students")
    search_term = st.text_input(
        "Search by roll number or student name",
        key="student_search",
    )

    students = get_students()

    if not students.empty and search_term.strip():
        search_term = search_term.strip()
        mask = (
            students["roll_no"].astype(str).str.contains(
                search_term, case=False, na=False
            )
            | students["name"].astype(str).str.contains(
                search_term, case=False, na=False
            )
        )
        students = students[mask]

    if students.empty:
        st.info("No student records found.")
        return

    st.dataframe(
        students.rename(
            columns={
                "roll_no": "Roll Number",
                "name": "Student Name",
                "department": "Department",
                "semester": "Semester",
                "attendance_present": "Classes Attended",
                "total_classes": "Total Classes",
                "internal_marks": "Internal Marks",
                "id": "Record ID",
            }
        ),
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("Delete Student Record")

    delete_options = {
        f"{row['roll_no']} — {row['name']}": int(row["id"])
        for _, row in students.iterrows()
    }

    selected_student = st.selectbox(
        "Choose a student",
        options=list(delete_options.keys()),
    )

    if st.button("🗑️ Delete Selected Student", type="secondary"):
        student_id = delete_options[selected_student]

        with get_connection() as conn:
            conn.execute(
                "DELETE FROM students WHERE id = ?",
                (student_id,),
            )

        st.success("Student record deleted.")
        st.rerun()


# =========================================================
# ASSIGNMENTS AND PRACTICALS
# =========================================================

def assignments_page():
    st.title("📝 Assignments & Practicals")
    st.write("Create academic tasks and track student submissions.")

    with st.expander("➕ Create New Assignment / Practical"):
        with st.form("create_task_form"):
            task_title = st.text_input("Task Title")

            task_type = st.selectbox(
                "Task Type",
                ["Assignment", "Practical", "Project", "Other"],
            )

            due_date = st.date_input(
                "Due Date",
                value=date.today(),
            )

            create_button = st.form_submit_button(
                "Create Task",
                type="primary",
            )

        if create_button:
            if not task_title.strip():
                st.error("Please enter a task title.")
            else:
                with get_connection() as conn:
                    cursor = conn.execute(
                        """
                        INSERT INTO tasks (title, task_type, due_date)
                        VALUES (?, ?, ?)
                        """,
                        (
                            task_title.strip(),
                            task_type,
                            due_date.isoformat(),
                        ),
                    )
                    new_task_id = cursor.lastrowid

                    students = conn.execute(
                        "SELECT id FROM students"
                    ).fetchall()

                    for student in students:
                        conn.execute(
                            """
                            INSERT OR IGNORE INTO submissions
                            (student_id, task_id, status)
                            VALUES (?, ?, 'Pending')
                            """,
                            (student["id"], new_task_id),
                        )

                st.success("Task created successfully.")
                st.rerun()

    tasks = get_tasks()

    if tasks.empty:
        st.info("No tasks have been created yet.")
        return

    st.subheader("Task List")

    display_tasks = tasks.rename(
        columns={
            "id": "Task ID",
            "title": "Title",
            "task_type": "Type",
            "due_date": "Due Date",
        }
    )
    st.dataframe(
        display_tasks,
        use_container_width=True,
        hide_index=True,
    )

    submissions = get_submissions()

    if not submissions.empty:
        st.subheader("Submission Summary")

        summary = (
            submissions.groupby(["task_title", "status"])
            .size()
            .unstack(fill_value=0)
        )

        for status in ["Submitted", "Pending", "Late"]:
            if status not in summary.columns:
                summary[status] = 0

        st.dataframe(
            summary[["Submitted", "Pending", "Late"]],
            use_container_width=True,
        )

    st.subheader("Update Student Submission Status")

    student_map = {}
    task_map = {}

    with get_connection() as conn:
        student_rows = conn.execute(
            "SELECT id, roll_no, name FROM students ORDER BY roll_no"
        ).fetchall()
        task_rows = conn.execute(
            "SELECT id, title FROM tasks ORDER BY title"
        ).fetchall()

    student_map = {
        f"{row['roll_no']} — {row['name']}": row["id"]
        for row in student_rows
    }
    task_map = {
        f"{row['title']} (ID {row['id']})": row["id"]
        for row in task_rows
    }

    if student_map and task_map:
        with st.form("update_submission_form"):
            selected_student_label = st.selectbox(
                "Student",
                list(student_map.keys()),
            )
            selected_task_label = st.selectbox(
                "Assignment / Practical",
                list(task_map.keys()),
            )
            new_status = st.selectbox(
                "Submission Status",
                ["Pending", "Submitted", "Late"],
            )

            update_button = st.form_submit_button(
                "Update Status",
                type="primary",
            )

        if update_button:
            student_id = student_map[selected_student_label]
            task_id = task_map[selected_task_label]

            with get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO submissions
                    (student_id, task_id, status)
                    VALUES (?, ?, ?)
                    ON CONFLICT(student_id, task_id)
                    DO UPDATE SET status = excluded.status
                    """,
                    (student_id, task_id, new_status),
                )

            st.success("Submission status updated.")
            st.rerun()

    st.subheader("Delete a Task")

    task_delete_map = {
        f"{row['title']} (ID {row['id']})": int(row["id"])
        for _, row in tasks.iterrows()
    }

    selected_task_to_delete = st.selectbox(
        "Choose task to delete",
        list(task_delete_map.keys()),
        key="delete_task_select",
    )

    if st.button("Delete Selected Task"):
        task_id = task_delete_map[selected_task_to_delete]

        with get_connection() as conn:
            conn.execute(
                "DELETE FROM tasks WHERE id = ?",
                (task_id,),
            )

        st.success("Task and its submission records deleted.")
        st.rerun()


# =========================================================
# ATTENDANCE TRACKER
# =========================================================

def attendance_page():
    st.title("📅 Attendance Tracker")
    st.write("Update attendance and identify students with shortages.")

    students = get_students()

    if students.empty:
        st.info("Add students before managing attendance.")
        return

    threshold = st.slider(
        "Minimum Required Attendance (%)",
        min_value=50,
        max_value=100,
        value=75,
        step=5,
    )

    students["attendance_percentage"] = students.apply(
        lambda row: calculate_attendance(
            row["attendance_present"],
            row["total_classes"],
        ),
        axis=1,
    )

    shortage_students = students[
        students["attendance_percentage"] < threshold
    ]

    col1, col2 = st.columns(2)
    col1.metric("Students Below Threshold", len(shortage_students))
    col2.metric("Attendance Threshold", f"{threshold}%")

    st.subheader("Current Attendance")

    st.dataframe(
        students[
            [
                "roll_no",
                "name",
                "attendance_present",
                "total_classes",
                "attendance_percentage",
            ]
        ].rename(
            columns={
                "roll_no": "Roll Number",
                "name": "Student Name",
                "attendance_present": "Classes Attended",
                "total_classes": "Total Classes",
                "attendance_percentage": "Attendance (%)",
            }
        ),
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("Update Attendance")

    student_map = {
        f"{row['roll_no']} — {row['name']}": int(row["id"])
        for _, row in students.iterrows()
    }

    with st.form("update_attendance_form"):
        selected_label = st.selectbox(
            "Select Student",
            list(student_map.keys()),
        )

        selected_id = student_map[selected_label]
        selected_row = students[students["id"] == selected_id].iloc[0]

        new_total = st.number_input(
            "Total Classes Held",
            min_value=0,
            max_value=10000,
            value=int(selected_row["total_classes"]),
            step=1,
        )

        new_present = st.number_input(
            "Classes Attended",
            min_value=0,
            max_value=10000,
            value=int(selected_row["attendance_present"]),
            step=1,
        )

        attendance_button = st.form_submit_button(
            "Save Attendance",
            type="primary",
        )

    if attendance_button:
        if new_present > new_total:
            st.error(
                "Classes attended cannot exceed total classes held."
            )
        else:
            with get_connection() as conn:
                conn.execute(
                    """
                    UPDATE students
                    SET attendance_present = ?, total_classes = ?
                    WHERE id = ?
                    """,
                    (int(new_present), int(new_total), selected_id),
                )

            st.success("Attendance updated successfully.")
            st.rerun()

    if not shortage_students.empty:
        st.subheader("⚠️ Attendance Defaulters")

        st.dataframe(
            shortage_students[
                [
                    "roll_no",
                    "name",
                    "attendance_percentage",
                ]
            ].rename(
                columns={
                    "roll_no": "Roll Number",
                    "name": "Student Name",
                    "attendance_percentage": "Attendance (%)",
                }
            ),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("No attendance defaulters at the selected threshold.")


# =========================================================
# INTERNAL MARKS
# =========================================================

def marks_page():
    st.title("📈 Internal Marks Management")
    st.write("Update internal marks and analyze student performance.")

    students = get_students()

    if students.empty:
        st.info("Add students before updating marks.")
        return

    st.subheader("Current Marks")

    st.dataframe(
        students[
            ["roll_no", "name", "semester", "internal_marks"]
        ].rename(
            columns={
                "roll_no": "Roll Number",
                "name": "Student Name",
                "semester": "Semester",
                "internal_marks": "Internal Marks",
            }
        ),
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("Update Student Marks")

    student_map = {
        f"{row['roll_no']} — {row['name']}": int(row["id"])
        for _, row in students.iterrows()
    }

    with st.form("update_marks_form"):
        selected_label = st.selectbox(
            "Select Student",
            list(student_map.keys()),
        )

        selected_id = student_map[selected_label]
        selected_row = students[students["id"] == selected_id].iloc[0]

        new_marks = st.number_input(
            "Internal Marks (out of 100)",
            min_value=0.0,
            max_value=100.0,
            value=float(selected_row["internal_marks"]),
            step=1.0,
        )

        marks_button = st.form_submit_button(
            "Save Marks",
            type="primary",
        )

    if marks_button:
        with get_connection() as conn:
            conn.execute(
                "UPDATE students SET internal_marks = ? WHERE id = ?",
                (float(new_marks), selected_id),
            )

        st.success("Internal marks updated successfully.")
        st.rerun()

    st.subheader("Marks Distribution")

    marks_chart = px.histogram(
        students,
        x="internal_marks",
        nbins=10,
        title="Distribution of Internal Marks",
        labels={"internal_marks": "Internal Marks"},
    )
    st.plotly_chart(marks_chart, use_container_width=True)

    average_marks = students["internal_marks"].mean()
    highest_marks = students["internal_marks"].max()
    lowest_marks = students["internal_marks"].min()

    col1, col2, col3 = st.columns(3)
    col1.metric("Average Marks", f"{average_marks:.2f}")
    col2.metric("Highest Marks", f"{highest_marks:.2f}")
    col3.metric("Lowest Marks", f"{lowest_marks:.2f}")


# =========================================================
# REPORTS AND CSV EXPORT
# =========================================================

def reports_page():
    st.title("📄 Reports & Export")
    st.write("View academic reports and download CSV files.")

    students = get_students()
    submissions = get_submissions()

    if students.empty:
        st.info("There are no student records to export.")
    else:
        students["attendance_percentage"] = students.apply(
            lambda row: calculate_attendance(
                row["attendance_present"],
                row["total_classes"],
            ),
            axis=1,
        )

        st.subheader("Student Academic Report")

        report = students[
            [
                "roll_no",
                "name",
                "department",
                "semester",
                "attendance_present",
                "total_classes",
                "attendance_percentage",
                "internal_marks",
            ]
        ].rename(
            columns={
                "roll_no": "Roll Number",
                "name": "Student Name",
                "department": "Department",
                "semester": "Semester",
                "attendance_present": "Classes Attended",
                "total_classes": "Total Classes",
                "attendance_percentage": "Attendance (%)",
                "internal_marks": "Internal Marks",
            }
        )

        st.dataframe(
            report,
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "⬇️ Download Student Academic Report (CSV)",
            data=report.to_csv(index=False).encode("utf-8"),
            file_name="student_academic_report.csv",
            mime="text/csv",
            use_container_width=True,
        )

    st.divider()
    st.subheader("Assignment Submission Report")

    if submissions.empty:
        st.info("No submission records available.")
    else:
        submission_report = submissions[
            [
                "roll_no",
                "student_name",
                "task_title",
                "task_type",
                "due_date",
                "status",
            ]
        ].rename(
            columns={
                "roll_no": "Roll Number",
                "student_name": "Student Name",
                "task_title": "Task",
                "task_type": "Task Type",
                "due_date": "Due Date",
                "status": "Submission Status",
            }
        )

        st.dataframe(
            submission_report,
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "⬇️ Download Submission Report (CSV)",
            data=submission_report.to_csv(index=False).encode("utf-8"),
            file_name="assignment_submission_report.csv",
            mime="text/csv",
            use_container_width=True,
        )


# =========================================================
# MAIN APPLICATION
# =========================================================

def main():
    initialize_database()

    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False

    if not st.session_state["authenticated"]:
        login_page()
        return

    with st.sidebar:
        st.title("📚 Faculty Tracker")
        st.write(
            f"Welcome, **{st.session_state.get('full_name', 'Faculty')}**"
        )
        st.caption(f"Username: {st.session_state['username']}")

        st.divider()

        page = st.radio(
            "Navigation",
            [
                "Dashboard",
                "Student Records",
                "Assignments & Practicals",
                "Attendance Tracker",
                "Internal Marks",
                "Reports & Export",
            ],
        )

        st.divider()

        if st.button("🚪 Logout", use_container_width=True):
            for key in [
                "authenticated",
                "faculty_id",
                "username",
                "full_name",
            ]:
                st.session_state.pop(key, None)

            st.rerun()

    if page == "Dashboard":
        dashboard_page()
    elif page == "Student Records":
        student_records_page()
    elif page == "Assignments & Practicals":
        assignments_page()
    elif page == "Attendance Tracker":
        attendance_page()
    elif page == "Internal Marks":
        marks_page()
    elif page == "Reports & Export":
        reports_page()


if __name__ == "__main__":
    main()
