# InvyPro 2.0 - Professional Inventory Management System

A modern, multi-organization inventory management system built with Streamlit and SQLite/PostgreSQL.
Try it here: [InvyPro 2.0](https://syndromic-ai-epidemic-alert-system-yqfnwwwdxawqrxjsucfhgv.streamlit.app/)

## App Screenshot:
![image alt](https://github.com/Omensah-15/Inventory-Manager-2.0/blob/6b4eaffa48608e201af7b7c13a02d7fa3803b021/App_screenshot.png)

## Features

- **Multi-Organization Support**: Complete data isolation between organizations
- **User Management**: Role-based access control (Admin/Manager/Staff)
- **Product Management**: SKU-based catalog with categories and suppliers
- **Inventory Tracking**: Real-time stock levels with reorder alerts
- **Transaction Recording**: Sales, purchases, adjustments
- **Supplier Management**: Maintain supplier information
- **Reporting**: Analytics and data visualization
- **Data Export**: CSV export functionality
- **Audit Logging**: Complete activity tracking

## Run Locally

Follow these steps to run **InventoryPro** on your local machine:

### Prerequisites
- Python 3.10+
- Git (optional, if cloning repo)

### 1. Clone the repository
```bash
git clone https://github.com/Omensah-15/Inventory-Manager-2.0.git
cd Inventory-Manager-2.0

2. Set up a virtual environment
python3 -m venv venv
source venv/bin/activate   # Linux/macOS
# .\venv\Scripts\activate  # Windows

3. Install dependencies
pip install -r requirements.txt

4.Run the app
streamlit run app_local.py

5. Optional: Custom database path
export INVYPRO_DB=/path/to/your/custom.db   # Linux/macOS
set INVYPRO_DB=C:\path\to\your\custom.db    # Windows
streamlit run app_local.py

```

## License: *MIT License — free to use and modify.*

## 👨‍💻 Author

**Developed by Mensah Obed**
[Email](mailto:heavenzlebron7@gmail.com) 
[LinkedIn](https://www.linkedin.com/in/obed-mensah-87001237b)
