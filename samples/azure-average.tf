############################################################
# AZURE AVERAGE INFRASTRUCTURE — MIXED GAPS
############################################################

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# ---------------------------------------------------------
# RESOURCE GROUP
# ---------------------------------------------------------

resource "azurerm_resource_group" "main" {
  name     = "app-rg"
  location = "East US"
}

# ---------------------------------------------------------
# VIRTUAL NETWORK
# ---------------------------------------------------------

resource "azurerm_virtual_network" "main" {
  name                = "app-vnet"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "app" {
  name                 = "app-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
}

# ---------------------------------------------------------
# NSG — SSH open to internet (gap)
# ---------------------------------------------------------

resource "azurerm_network_security_group" "app_nsg" {
  name                = "app-nsg"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
}

resource "azurerm_network_security_rule" "allow_ssh" {
  name                        = "AllowSSH"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.app_nsg.name
}

resource "azurerm_network_security_rule" "allow_https" {
  name                        = "AllowHTTPS"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "10.0.0.0/16"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.app_nsg.name
}

# ---------------------------------------------------------
# STORAGE ACCOUNT — HTTPS enforced, but no lifecycle
# ---------------------------------------------------------

resource "azurerm_storage_account" "data" {
  name                     = "appdatastorage123"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  enable_https_traffic_only = true
  min_tls_version           = "TLS1_2"
}

# ---------------------------------------------------------
# KEY VAULT — no purge protection (gap)
# ---------------------------------------------------------

resource "azurerm_key_vault" "main" {
  name                = "app-keyvault-123"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku_name            = "standard"
  tenant_id           = var.tenant_id

  purge_protection_enabled = false
}

# ---------------------------------------------------------
# SQL DATABASE — not zone-redundant (gap)
# ---------------------------------------------------------

resource "azurerm_mssql_server" "main" {
  name                         = "app-sql-server"
  resource_group_name          = azurerm_resource_group.main.name
  location                     = azurerm_resource_group.main.location
  version                      = "12.0"
  administrator_login          = var.sql_admin
  administrator_login_password = var.sql_password
}

resource "azurerm_mssql_database" "main" {
  name      = "app-database"
  server_id = azurerm_mssql_server.main.id
  sku_name  = "GP_S_Gen5_2"

  zone_redundant = false
  max_size_gb    = 50
}

# ---------------------------------------------------------
# LINUX VM — no availability zone (gap)
# ---------------------------------------------------------

resource "azurerm_linux_virtual_machine" "app" {
  name                = "app-vm"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  size                = "Standard_B2ms"

  admin_username = "adminuser"

  admin_ssh_key {
    username   = "adminuser"
    public_key = var.ssh_public_key
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  network_interface_ids = [azurerm_network_interface.app.id]

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }
}

resource "azurerm_network_interface" "app" {
  name                = "app-nic"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.app.id
    private_ip_address_allocation = "Dynamic"
  }
}

# ---------------------------------------------------------
# VARIABLES
# ---------------------------------------------------------

variable "tenant_id" {
  type = string
}

variable "sql_admin" {
  type = string
}

variable "sql_password" {
  type      = string
  sensitive = true
}

variable "ssh_public_key" {
  type = string
}
