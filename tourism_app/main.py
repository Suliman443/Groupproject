import streamlit as st
from db import create_tables, insert_event, fetch_events

st.set_page_config(page_title="Tourism Event Manager", layout="wide")
st.title("🎉 Smart Tourism Event Management")

# Initialize DB
create_tables()

# --- Add New Event ---
st.header("Add a New Event")
with st.form("add_event_form"):
    title = st.text_input("Event Title")
    description = st.text_area("Description")
    location = st.text_input("Location")
    date = st.date_input("Date")
    image = st.text_input("Image URL (optional)")
    submitted = st.form_submit_button("Add Event")

    if submitted:
        insert_event(title, description, location, str(date), image)
        st.success("✅ Event added successfully!")

# --- Show Events ---
st.header("📅 Upcoming Events")
events = fetch_events()

for event in events:
    with st.container():
        st.subheader(event["title"])
        st.write(event["description"])
        st.write(f"📍 {event['location']} | 🗓️ {event['date']}")
        if event["image"]:
            st.image(event["image"], width=300)
        st.markdown("---")
