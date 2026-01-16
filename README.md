# InvyPro 2.0 - Professional Inventory Management System

A powerful, modern, and user-friendly inventory management system built with Streamlit and SQLite/PostgreSQL. Perfect for small to medium-sized businesses looking for a complete inventory solution.

**TRY IT HERE**: [InvyPro 2.0](https://syndromic-ai-epidemic-alert-system-yqfnwwwdxawqrxjsucfhgv.streamlit.app/)

## App Demo Screenshots:
![image alt](https://github.com/Omensah-15/Inventory-Manager-2.0/blob/cae9500074e21d75fea8587b4092ca7dee97a912/docs/screenshots/Dashboard.png)
![image alt](https://github.com/Omensah-15/Inventory-Manager-2.0/blob/cae9500074e21d75fea8587b4092ca7dee97a912/docs/screenshots/Reports%26Analytics.png)
![image alt](https://github.com/Omensah-15/Inventory-Manager-2.0/blob/cae9500074e21d75fea8587b4092ca7dee97a912/docs/screenshots/settings.png)

## Features Overview

#### **Multi-Organization Support**
- Complete data isolation between organizations
- Secure organization-level access control
- Dedicated inventory space per organization

#### **Security & Access Control**
- Role-based permissions (Admin/Manager/Staff)
- Secure authentication with PBKDF2-SHA256 hashing
- Session timeout management
- Activity logging for all user actions
- SQL injection prevention

#### **Product Management**
- SKU-based product catalog with barcode support
- Categories, classifications, and location tracking
- Supplier linkage and multiple units of measurement
- Cost and selling price management

#### **Inventory Tracking**
- Real-time stock level monitoring
- Low stock alerts and reorder management
- Automatic stock updates on transactions
- Stock valuation by cost and selling price

#### **Transaction System**
- Sales recording with reference numbers
- Purchase recording from suppliers
- Stock adjustments and inter-location transfers
- Full audit trail with searchable history

#### **Supplier Management**
- Comprehensive supplier database
- Contact information and payment terms
- Address management with status tracking

#### **Analytics & Reporting**
- Sales analytics with daily/monthly trends
- Inventory valuation and category analysis
- Interactive dashboards with Plotly/Altair
- Custom date range reporting
- Top products and stock distribution

#### **Backup & Restore**
- One-click manual backups
- Automatic backup on startup
- Point-in-time restore capability
- Backup management and cleanup tools

#### **Data Export Center**
- CSV/Excel exports for all data tables
- Complete database backup in Excel format
- Custom reports and filtered transaction exports

#### **Audit & Compliance**
- Complete activity tracking
- User login/logout logging
- Product and transaction change logs
- Searchable audit history

#### **User Interface**
- Professional, responsive design
- Mobile-friendly layout with intuitive navigation
- Color-coded status indicators
- Interactive data tables and real-time metrics

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
streamlit run app.py

5. Optional: Custom database path
export INVYPRO_DB=/path/to/your/custom.db   # Linux/macOS
set INVYPRO_DB=C:\path\to\your\custom.db    # Windows
streamlit run app.py

```

## License: *MIT License — free to use and modify.*

## 👨‍💻 Author

**Developed by Mensah Obed**
[Email](mailto:heavenzlebron7@gmail.com) 
[LinkedIn](https://www.linkedin.com/in/obed-mensah-87001237b)
