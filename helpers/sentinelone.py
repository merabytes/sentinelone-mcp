import os
import requests
from functools import wraps
import aiohttp
import asyncio
import time
from datetime import datetime, timedelta
import json
import logging
from helpers.dag_notifier import DagNotifier, dag_node
from helpers.base import BaseHelper

# Initialize module logger
logger = logging.getLogger(__name__)

# Helper function to convert date to timestamp format
def convert_to_timestamp(dt):
    return int(dt.timestamp() * 1000)

# Helper function to clean ID lists (remove null, empty string, "null" string)
def clean_id_list(values):
    """
    Sanitize a list of IDs by removing null, empty, or invalid values.
    
    Args:
        values: List or single value that may contain nulls
        
    Returns:
        List of valid IDs (non-null, non-empty strings)
    """
    if not values:
        return []
    
    # Handle single value
    if not isinstance(values, list):
        values = [values]
    
    # Filter out null, empty string, and "null" string
    return [v for v in values if v not in (None, "", "null") and v]

class SentinelOneHelper(DagNotifier, BaseHelper):
    BRAND      = "SentinelOne"
    ACCENT     = "#6a3fa0"
    CREDENTIAL         = ("S1_API_KEY", "S1_API_URL")
    CREDENTIAL_KWARGS_MAP = {
        "S1_API_KEY": "api_key",
        "S1_API_URL": "api_url",
    }
    CONNECTION      = "EDRConnection?service=sentinelone"
    CATEGORY="security"
    FAVICON            = "sentinelone"
    ACCENT             = "#4A26AB"
    @classmethod
    def node_prefix(cls) -> str:
        return "sentinelone"
    def __init__(self, api_key, api_url=None):
        self.api_key = api_key
        if not api_url:
            raise ValueError("api_url is required")
        raw_url = api_url
        # Normalize: strip any trailing /web/api/... path — we always append it ourselves
        from urllib.parse import urlparse
        parsed = urlparse(raw_url)
        self.api_url = f"{parsed.scheme}://{parsed.netloc}"
        self.account_id = None
        self.site_id = None
        self.headers = {
            'authorization': f'ApiToken {self.api_key}',
            'accept': 'application/json, */*',
            'accept-language': 'en',
            'content-type': 'application/json',
            'origin': self.api_url,
        }
        self.alert_handlers = []
        self.processed_alert_ids = set()
        self.last_alert_id = None

    def _configured_site_ids(self) -> list[str] | None:
        """Site IDs from helper.site_id (comma-separated or list). None = no filter."""
        if not self.site_id:
            return None
        if isinstance(self.site_id, list):
            return clean_id_list(self.site_id) or None
        return clean_id_list(str(self.site_id).split(",")) or None

    # Asynchronous fetch method
    async def async_fetch(self, url, params):
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, headers=self.headers, params=params) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    response.raise_for_status()

    # Synchronous fetch method
    def fetch(self, url, params=None):
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()

    # Asynchronous post method
    async def async_post(self, url, json_data):
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.post(url, headers=self.headers, json=json_data) as response:
                if response.status in [200, 201]:
                    return await response.json()
                else:
                    response.raise_for_status()

    # Synchronous post method
    def post(self, url, json_data):
        response = requests.post(url, headers=self.headers, json=json_data)
        response.raise_for_status()
        return response.json()
    
    def put(self, url, json_data):
        response = requests.put(url, headers=self.headers, json=json_data)
        print(response.text)
        return response.json()

    # Asynchronous get_alerts method
    async def async_get_alerts(self, **kwargs):
        url = f"{self.api_url}/web/api/v2.1/cloud-detection/alerts"
        return await self.async_fetch(url, kwargs)

    # Synchronous get_alerts method
    @dag_node('sentinelone__get_alerts', label='get alerts')
    def get_alerts(self, **kwargs):
        url = f"{self.api_url}/web/api/v2.1/cloud-detection/alerts"
        return self.fetch(url, kwargs)

    @dag_node('sentinelone__get_accounts', label='get accounts')
    def get_accounts(self):
        """
        Obtiene la lista de cuentas disponibles en SentinelOne.
        """
        url = f"{self.api_url}/web/api/v2.1/accounts"

        try:
            print(f"🔍 Enviando request a SentinelOne: {url}")  
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            response_json = response.json()  # Obtener JSON de la respuesta
            
            # Extraer las cuentas correctamente
            accounts = response_json.get("data", [])
            if not isinstance(accounts, list):  # Asegurar que sea una lista
                print("⚠️ La API devolvió datos pero no es una lista de cuentas.")
                return None
            
            print(f"✅ Cuentas obtenidas: {len(accounts)} cuentas encontradas.")  # Mostrar cuántas cuentas hay
            return accounts

        except requests.exceptions.RequestException as e:
            print(f"❌ Error obteniendo las cuentas: {e}")
            return None


    
    
    # Synchronous get_sites method
    @dag_node('sentinelone__get_sites', label='get sites')
    def get_sites(self, account_id=None):
        url = f"{self.api_url}/web/api/v2.1/sites"
        params = {}

        if account_id:
            params["accountIds"] = account_id  # 🔥 PASAMOS EL ID CORRECTAMENTE

        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()

            response_json = response.json()

            # Validamos si la API devolvió datos
            if "data" in response_json and "sites" in response_json["data"]:
                all_sites = response_json["data"]["sites"]
            else:
                print("⚠️ No se encontraron sitios en la respuesta de la API.")
                return []

            # 🔥 Filtrado manual adicional por `accountId`
            filtered_sites = [site for site in all_sites if site["accountId"] == account_id]

            if not filtered_sites:
                print(f"⚠️ No se encontraron sitios dentro de la cuenta con ID {account_id}.")
                return []

            return filtered_sites

        except requests.exceptions.RequestException as e:
            print(f"❌ Error obteniendo los sitios: {e}")
            return []

    def find_site_by_domain(self, domain: str, account_id: str):
        """
        Find a SentinelOne site by name or externalId within an account.

        Returns:
            Site dict if found, else None.
        """
        domain = (domain or "").strip().lower()
        if not domain or not account_id:
            return None

        url = f"{self.api_url}/web/api/v2.1/sites"
        params = {"accountIds": str(account_id), "limit": 500}
        try:
            response = requests.get(
                url, headers=self.headers, params=params, timeout=30
            )
            response.raise_for_status()
            payload = response.json()
            sites = payload.get("data", {})
            if isinstance(sites, dict):
                sites = sites.get("sites", [])
            if not isinstance(sites, list):
                sites = []
            for site in sites:
                name = (site.get("name") or "").lower()
                ext = (site.get("externalId") or "").lower()
                if name == domain or ext == domain:
                    return site
        except requests.RequestException as exc:
            logger.warning("S1 find site by domain failed: %s", exc)
        return None

    def create_site(
        self,
        name: str,
        account_id: str,
        external_id: str = None,
        sku: str = "Complete",
        site_type: str = "Trial",
        total_licenses: int = 1,
        inherits: bool = True,
    ) -> dict:
        """
        Create a SentinelOne site.

        Args:
            name: Site name (typically the client domain)
            account_id: SentinelOne account ID
            external_id: External identifier (defaults to name)
            sku: License SKU (default Complete)
            site_type: Site type (default Trial)
            total_licenses: License count (default 1)
            inherits: Inherit account policy (default True)

        Returns:
            Created site data dict (includes id, name, etc.)
        """
        domain = (name or "").strip().lower()
        external_id = (external_id or domain).strip().lower()
        url = f"{self.api_url}/web/api/v2.1/sites"
        body = {
            "data": {
                "name": domain,
                "externalId": external_id,
                "inherits": inherits,
                "accountId": str(account_id),
                "sku": sku,
                "siteType": site_type,
                "totalLicenses": total_licenses,
            }
        }
        logger.info("Creating SentinelOne site: %s", domain)
        result = self.post(url, body)
        site_data = result.get("data") or result
        logger.info(
            "Successfully created SentinelOne site with ID: %s",
            site_data.get("id"),
        )
        return site_data

    async def async_get_application_inventory(self, agent_id, **kwargs):
        url = f'{self.api_url}/web/api/v2.1/application-management/endpoints/{agent_id}/applications'
        return await self.async_fetch(url, kwargs)
    
    # Hay paginacion
    def get_all_agents(self, **kwargs):
        url = f'{self.api_url}/web/api/v2.1/agents'
        return self.fetch(url, kwargs)
    
    def get_agents_info(self, account_id, site_id, group_id=None):
        url = f'{self.api_url}/web/api/v2.1/agents'
        params = {
            'accountIds': account_id,
            'siteIds': site_id,
            'limit': 1000
        }
        if group_id:
            params['groupIds'] = group_id
        return self.fetch(url, params)

    @dag_node('sentinelone__get_agent_apps', label='agent apps')
    def get_agent_apps(self, agent_name, account_id, site_id, group_id):
        url = f'{self.api_url}/web/api/v2.1/application-management/risks/applications'
        params = {
                'accountIds': account_id,
                'groupIds': group_id,
                'siteIds': site_id,
                'endpointName__contains': agent_name
            }
        
        return self.fetch(url, params)
    
    # Synchronous get_application_inventory method
    def get_application_inventory(self, agent_id, **kwargs):
        # Intentemos obtener toda la información del agente
        url = f'{self.api_url}/web/api/v2.1/applications/{agent_id}'
        print(f"Attempting to access URL: {url}")
        return self.fetch(url, kwargs)


    # Asynchronous get_cves method
    async def async_get_cves(self, application_id, **kwargs):
        url = f'{self.api_url}/web/api/v2.1/application-management/applications/{application_id}/cves'
        return await self.async_fetch(url, kwargs)

    # Synchronous get_cves method
    @dag_node('sentinelone__get_cves', label='get CVEs')
    def get_cves(self, scan_id: str = '', application_id: str = '', account_id: str = '') -> list[dict]:
        """Retrieve CVEs for a specific application with pagination."""
        url = f'{self.api_url}/web/api/v2.1/application-management/risks/cves'
        
        all_cves = []
        next_cursor = None
        
        try:
            while True:
                # Preparar parámetros para cada solicitud
                params = {'accountIds': account_id, 'applicationIds': application_id, 'limit': 600, 'sortBy': 'severity', 'sortOrder': 'desc'}
                if next_cursor:
                    params['cursor'] = next_cursor
                
                # Hacer la solicitud usando el método fetch existente
                response = self.fetch(url, params)

                print(response)
                
                # Convertir la respuesta a diccionario si es una cadena
                if isinstance(response, str):
                    try:
                        response = json.loads(response)
                    except json.JSONDecodeError:
                        print(f"Error: No se pudo decodificar la respuesta JSON")
                        break
                
                # Verificar si la respuesta es válida
                if not isinstance(response, dict) or 'data' not in response:
                    break
                    
                # Extraer datos de la respuesta
                cves = response.get('data', [])
                all_cves.extend(cves)
                
                # Verificar si hay más páginas
                pagination = response.get('pagination', {})
                next_cursor = pagination.get('nextCursor')
                
                if not next_cursor:
                    break  # No hay más páginas
            
            # Devolver los CVEs recopilados en formato string JSON
            return json.dumps({"data": all_cves})
            
        except Exception as e:
            logging.info(f"Error obteniendo CVEs: {e}")
            return json.dumps({"data": []})  # Devolver JSON vacío en caso de error
    
    
    @dag_node('sentinelone__get_agents', label='get agents')
    def get_agents(self, site_id, group_id=None, limit=200, cursor=None):
        """
        Obtiene los agentes de SentinelOne filtrados por Site y, opcionalmente, por Group.
        Implementa paginación para obtener más de 10 agentes.

        If filtering by siteIds returns 403 (token lacks per-site scope),
        falls back to fetching all agents and filtering client-side.
        """
        site_ids_param = ",".join(site_id) if isinstance(site_id, list) else str(site_id)
        site_ids_set = set(site_ids_param.split(","))

        def _build_url(with_site=True, cursor=None):
            url = f"{self.api_url}/web/api/v2.1/agents?limit={limit}"
            if with_site:
                url += f"&siteIds={site_ids_param}"
            if group_id:
                url += f"&groupIds={group_id}"
            if cursor:
                url += f"&cursor={cursor}"
            return url

        def _fetch_all(with_site):
            all_agents = []
            url = _build_url(with_site=with_site)
            while True:
                data = self.fetch(url)
                agents = data.get('data', [])
                all_agents.extend(agents)
                next_cursor = data.get('pagination', {}).get('nextCursor')
                if not next_cursor:
                    break
                url = _build_url(with_site=with_site, cursor=next_cursor)
            return all_agents

        try:
            agents = _fetch_all(with_site=True)
        except Exception as e:
            if '403' in str(e) or 'FORBIDDEN' in str(e).upper():
                logger.warning(
                    f"get_agents: siteIds={site_ids_param} returned 403, "
                    "retrying without siteIds and filtering client-side"
                )
                all_agents = _fetch_all(with_site=False)
                # Filter client-side by siteId field
                agents = [a for a in all_agents if str(a.get('siteId', '')) in site_ids_set]
            else:
                raise

        return {"data": agents}

    @dag_node('sentinelone__get_agent_inventory', label='agent inventory')
    def get_agent_inventory(self, scan_id: str = '', agent_id: str = '') -> dict:
        """Retrieve installed applications inventory for a specific agent."""
        url = f"{self.api_url}/web/api/v2.1/application-management/inventory/applications"
        params = {'ids': agent_id}
        return self.fetch(url, params=params)

    
    @dag_node('sentinelone__get_app_inventory', label='app inventory')
    def get_app_inventory(self, scan_id: str = '', account_id: str = '', site_id: str = '', application_name: str = '', application_vendor: str = '', limit: int = 1000) -> dict:
        """Fetch endpoints with a specific application installed from inventory."""
        url = (f"{self.api_url}/web/api/v2.1/application-management/inventory/endpoints")

        params = {'applicationName': application_name, 
                  'applicationVendor': application_vendor, 
                  'accountIds': account_id, 
                  'siteIds': site_id, 
                  'limit': limit}

        return self.fetch(url, params=params)

    def get_agents_missing_ninjarmm_json(self, site_id, account_id):
        """
        Devuelve un JSON con los agentes que NO tienen NinjaRMM instalado,
        consultando directamente contra SentinelOne.
        """

        data = self.get_app_inventory(account_id, site_id, "NinjaRMMAgent", "NinjaRMM LLC")
  
        ninja_installed = {item["endpointId"]: item for item in data.get("data", [])}

        # 2. Obtener todos los agentes del sitio (SentinelOne base)
        agents_data = self.get_agents(site_id)

        # 3. Filtrar los que NO están en la lista de endpoints con NinjaRMMAgent
        agents_without_ninja = []
        for agent in agents_data.get("data", []):
            agent_id = agent.get("id")
            if not agent_id:
                continue

            if agent_id not in ninja_installed:
                agents_without_ninja.append({
                    "id": agent.get("id"),
                    "computer_name": agent.get("computerName", "Unknown"),
                    "ip_address": (
                        agent.get("networkInterfaces", [{}])[0].get("lastIpToMgmt")
                        or agent.get("lastIpToMgmt", "IP desconocida")
                    ),
                    "status": agent.get("networkStatus", "unknown").title(),
                })

        return {
            "total_agents": agents_data.get("pagination", {}).get("totalItems", len(agents_data.get("data", []))),
            "agents_missing_ninjarmm_count": len(agents_without_ninja),
            "agents_missing_ninjarmm": agents_without_ninja
        }

    def get_agents_missing_ninjarmm(self, site_id):
        """
        Imprime en formato WhatsApp los agentes que no tienen NinjaRMM instalado,
        mostrando 'computerName' y 'lastIpToMgmt'.
        """
        agents_data = self.get_agents(site_id)
        agents_without_ninja = []

        for agent in agents_data.get("data", []):
            agent_id = agent.get("id")
            if not agent_id:
                continue

            inventory_data = self.get_agent_inventory(agent_id)
            apps = inventory_data.get("data", [])

            if not any(app.get("name") == "NinjaRMMAgent" for app in apps):
                agents_without_ninja.append(agent)

        print("\n🛑 Equipos sin *NinjaRMM*:\n")
        for agent in agents_without_ninja:
            name = agent.get("computerName", "Unknown")
            ip = agent.get("networkInterfaces", [{}])[0].get("lastIpToMgmt") or agent.get("lastIpToMgmt", "IP desconocida")
            status = agent.get("networkStatus").title()
            print(f"- {name} ({ip}) ({status})")

        return agents_without_ninja

    def get_agents_missing_duo_json(self, site_id, account_id):
        """
        Devuelve un JSON con los agentes que NO tienen Duo Cisco instalado,
        consultando directamente contra SentinelOne.
        """

        data = self.get_app_inventory(account_id, site_id, "Duo Authentication for Windows Logon x64", "Duo Security Inc.")

        ninja_installed = {item["endpointId"]: item for item in data.get("data", [])}

        # 2. Obtener todos los agentes del sitio (SentinelOne base)
        agents_data = self.get_agents(site_id)

        # 3. Filtrar los que NO están en la lista de endpoints con NinjaRMMAgent
        agents_without_ninja = []
        for agent in agents_data.get("data", []):
            agent_id = agent.get("id")
            if not agent_id:
                continue

            if agent_id not in ninja_installed:
                agents_without_ninja.append({
                    "id": agent.get("id"),
                    "computer_name": agent.get("computerName", "Unknown"),
                    "ip_address": (
                        agent.get("networkInterfaces", [{}])[0].get("lastIpToMgmt")
                        or agent.get("lastIpToMgmt", "IP desconocida")
                    ),
                    "status": agent.get("networkStatus", "unknown").title(),
                })

        return {
            "total_agents": agents_data.get("pagination", {}).get("totalItems", len(agents_data.get("data", []))),
            "agents_missing_duo_count": len(agents_without_ninja),
            "agents_missing_duo": agents_without_ninja
        }

    def get_agents_missing_duo(self, site_id):
        """
        Imprime en formato WhatsApp los agentes que no tienen Duo instalado,
        mostrando 'computerName' y 'lastIpToMgmt'.
        """
        agents_data = self.get_agents(site_id)
        agents_without_duo = []

        for agent in agents_data.get("data", []):
            agent_id = agent.get("id")
            if not agent_id:
                continue

            inventory_data = self.get_agent_inventory(agent_id)
            apps = inventory_data.get("data", [])

            if not any(app.get("name") == "Duo Authentication for Windows Logon x64" for app in apps):
                agents_without_duo.append(agent)

        print("\n🛑 Equipos sin *Duo*:\n")
        for agent in agents_without_duo:
            name = agent.get("computerName", "Unknown")
            ip = agent.get("networkInterfaces", [{}])[0].get("lastIpToMgmt") or agent.get("lastIpToMgmt", "IP desconocida")
            status = agent.get("networkStatus").title()
            print(f"- {name} ({ip}) ({status})")

        return agents_without_duo
    
    def get_agents_with_docker_json(self, site_id, account_id):
        """
        Devuelve un JSON con los agentes que TIENEN Docker instalado,
        detectando aplicaciones con nombre "docker-ce" o "Docker Desktop".
        """
        # 1. Buscar endpoints con docker-ce instalado
        docker_ce_data = self.get_app_inventory(account_id, site_id, "docker-ce", "Docker &lt;support@docker.com&gt;")
        docker_ce_installed = {item["endpointId"]: item for item in docker_ce_data.get("data", [])}
        
        # 2. Buscar endpoints con Docker Desktop instalado
        docker_desktop_data = self.get_app_inventory(account_id, site_id, "Docker Desktop", "Docker Inc.")
        docker_desktop_installed = {item["endpointId"]: item for item in docker_desktop_data.get("data", [])}
        
        # 3. Combinar ambos conjuntos de endpoints con Docker
        all_docker_endpoints = {}
        all_docker_endpoints.update(docker_ce_installed)
        all_docker_endpoints.update(docker_desktop_installed)
        
        # 4. Obtener todos los agentes del sitio para construir lista completa
        agents_data = self.get_agents(site_id)
        
        # 5. Construir lista de agentes con Docker
        agents_with_docker = []
        for agent in agents_data.get("data", []):
            agent_id = agent.get("id")
            if not agent_id:
                continue
            
            if agent_id in all_docker_endpoints:
                agents_with_docker.append({
                    "id": agent.get("id"),
                    "computer_name": agent.get("computerName", "Unknown"),
                    "ip_address": (
                        agent.get("networkInterfaces", [{}])[0].get("lastIpToMgmt")
                        or agent.get("lastIpToMgmt", "IP desconocida")
                    ),
                    "status": agent.get("networkStatus", "unknown").title(),
                })
        
        return {
            "total_agents": agents_data.get("pagination", {}).get("totalItems", len(agents_data.get("data", []))),
            "agents_with_docker_count": len(agents_with_docker),
            "agents_with_docker": agents_with_docker
        }
    
    def get_agents_with_anydesk_json(self, site_id, account_id):
        """
        Devuelve un JSON con los agentes que TIENEN AnyDesk instalado,
        detectando aplicaciones con nombre "AnyDesk" y publisher "AnyDesk Software GmbH".
        """
        # Buscar endpoints con AnyDesk instalado
        anydesk_data = self.get_app_inventory(account_id, site_id, "AnyDesk", "AnyDesk Software GmbH")
        anydesk_installed = {item["endpointId"]: item for item in anydesk_data.get("data", [])}
        
        # Obtener todos los agentes del sitio para construir lista completa
        agents_data = self.get_agents(site_id)
        
        # Construir lista de agentes con AnyDesk
        agents_with_anydesk = []
        for agent in agents_data.get("data", []):
            agent_id = agent.get("id")
            if not agent_id:
                continue
            
            if agent_id in anydesk_installed:
                agents_with_anydesk.append({
                    "id": agent.get("id"),
                    "computer_name": agent.get("computerName", "Unknown"),
                    "ip_address": (
                        agent.get("networkInterfaces", [{}])[0].get("lastIpToMgmt")
                        or agent.get("lastIpToMgmt", "IP desconocida")
                    ),
                    "status": agent.get("networkStatus", "unknown").title(),
                })
        
        return {
            "total_agents": agents_data.get("pagination", {}).get("totalItems", len(agents_data.get("data", []))),
            "agents_with_anydesk_count": len(agents_with_anydesk),
            "agents_with_anydesk": agents_with_anydesk
        }
    
    def get_agents_with_teamviewer_json(self, site_id, account_id):
        """
        Devuelve un JSON con los agentes que TIENEN TeamViewer instalado,
        detectando aplicaciones con nombre "TeamViewer Host" o "TeamViewer" y publisher "TeamViewer".
        """
        # 1. Buscar endpoints con TeamViewer Host instalado
        teamviewer_host_data = self.get_app_inventory(account_id, site_id, "TeamViewer Host", "TeamViewer")
        teamviewer_host_installed = {item["endpointId"]: item for item in teamviewer_host_data.get("data", [])}
        
        # 2. Buscar endpoints con TeamViewer instalado
        teamviewer_data = self.get_app_inventory(account_id, site_id, "TeamViewer", "TeamViewer")
        teamviewer_installed = {item["endpointId"]: item for item in teamviewer_data.get("data", [])}
        
        # 3. Combinar ambos conjuntos de endpoints con TeamViewer
        all_teamviewer_endpoints = {}
        all_teamviewer_endpoints.update(teamviewer_host_installed)
        all_teamviewer_endpoints.update(teamviewer_installed)
        
        # 4. Obtener todos los agentes del sitio para construir lista completa
        agents_data = self.get_agents(site_id)
        
        # 5. Construir lista de agentes con TeamViewer
        agents_with_teamviewer = []
        for agent in agents_data.get("data", []):
            agent_id = agent.get("id")
            if not agent_id:
                continue
            
            if agent_id in all_teamviewer_endpoints:
                agents_with_teamviewer.append({
                    "id": agent.get("id"),
                    "computer_name": agent.get("computerName", "Unknown"),
                    "ip_address": (
                        agent.get("networkInterfaces", [{}])[0].get("lastIpToMgmt")
                        or agent.get("lastIpToMgmt", "IP desconocida")
                    ),
                    "status": agent.get("networkStatus", "unknown").title(),
                })
        
        return {
            "total_agents": agents_data.get("pagination", {}).get("totalItems", len(agents_data.get("data", []))),
            "agents_with_teamviewer_count": len(agents_with_teamviewer),
            "agents_with_teamviewer": agents_with_teamviewer
        }
        

    # Asynchronous get_applications method
    async def async_get_applications(self, **kwargs):
        url = f'{self.api_url}/web/api/v2.1/application-management/risks/applications'
        return await self.async_fetch(url, kwargs)

    # Synchronous get_applications method
    @dag_node('sentinelone__get_applications', label='get apps')
    def get_applications(self, agent_id):
        url = f'{self.api_url}/web/api/v2.1/applications'  # Ajusta la URL si es necesario
        params = {'agentIds': agent_id}  # Asumiendo que se usa agentIds como filtro
        return self.fetch(url, params)

    # Asynchronous get_endpoints method
    async def async_get_endpoints(self, **kwargs):
        url = f'{self.api_url}/web/api/v2.1/application-management/risks/endpoints'
        return await self.async_fetch(url, kwargs)
    
    
    @dag_node('sentinelone__get_groups', label='get groups')
    def get_groups(self, scan_id: str = '', site_id: str = '', account_id: str | None = None, limit: int = 300) -> dict:
        """Retrieve groups within a specific site."""
        site_ids_param = ",".join(site_id) if isinstance(site_id, list) else str(site_id)
        params = {
            'accountIds': account_id,
            'siteIds': site_ids_param,
            'limit':limit
        }
        url = f"{self.api_url}/web/api/v2.1/groups"
        return self.fetch(url, params)


    # Synchronous get_endpoints method
    @dag_node('sentinelone__get_endpoints', label='get endpoints')
    def get_endpoints(self, **kwargs):
        params = {
            'limit': '50',
            'accountIds': self.account_id,
            'applicationIds': kwargs.get('application_ids'),
        }
        url = f'{self.api_url}/web/api/v2.1/application-management/risks/endpoints'
        return self.fetch(url, params)

    # Asynchronous get_cve method
    async def async_get_cve(self, **kwargs):
        url = f'{self.api_url}/web/api/v2.1/application-management/risks/cves'
        return await self.async_fetch(url, kwargs)

    @dag_node('sentinelone__get_cve', label='get CVE')
    def get_cve(self, scan_id: str = '', **kwargs) -> dict:
        """Retrieve CVEs for applications filtered by account."""
        params = {
            'limit': '50',
            'sortBy': 'severity',
            'sortOrder': 'desc',
            'accountIds': self.account_id,
            'applicationIds': kwargs.get('application_ids'),
        }
        url = f'{self.api_url}/web/api/v2.1/application-management/risks/cves'
        return self.fetch(url, params)

    @dag_node('sentinelone__get_rules', label='get rules')
    def get_rules(self, scan_id: str = '', **kwargs) -> dict:
        """Retrieve cloud detection rules for the account."""
        params = {'limit': '1000'}
        if self.account_id:
            params['accountIds'] = self.account_id
        url = f'{self.api_url}/web/api/v2.1/cloud-detection/rules'
        return self.fetch(url, params)

    @dag_node('sentinelone__get_site_token', label='site token')
    def get_site_token(self, scan_id: str = '', site_id: str = '') -> str:
        """Retrieve the registration token for a specific site."""
        url = f'{self.api_url}/web/api/v2.1/sites/{site_id}/token'
        data = self.fetch(url, params={})
        return data['data']['token']
    
    @dag_node('sentinelone__reactivate_site', label='reactivate site')
    def reactivate_site(self, scan_id: str = '', site_id: str = '', **kwargs) -> dict:
        """Reactivate a SentinelOne site with unlimited expiration."""
        if not site_id:
            raise ValueError("site_id is required for reactivate_site")
        url = f'{self.api_url}/web/api/v2.1/sites/{site_id}/reactivate'
        return self.put(url, json_data={
                        "data": {
                            "expiration": None,
                            "unlimited": True
                        }
                    })
    
    @dag_node('sentinelone__reactivate_account', label='reactivate account')
    def reactivate_account(self, scan_id: str = '', account_id: str = '', **kwargs) -> dict:
        """Reactivate a SentinelOne account with unlimited expiration."""
        if not account_id:
            raise ValueError("account_id is required for reactivate_account")
        url = f'{self.api_url}/web/api/v2.1/accounts/{account_id}/reactivate'
        return self.put(url, json_data={
                        "data": {
                            "expiration": None,
                            "unlimited": True
                        }
                    })

    @dag_node('sentinelone__create_powerquery', label='create powerquery')
    def create_powerquery(self, scan_id: str = '', from_date=None, to_date=None, query: str = '', limit: int = 20000, site_ids: list | None = None) -> dict:
        """Initialize a Deep Visibility query using the DV runtime API."""
        from_timestamp = convert_to_timestamp(from_date)
        to_timestamp = convert_to_timestamp(to_date)

        # Build base payload
        json_data = {
            "fromDate": from_timestamp,
            "query": query,
            "limit": limit,
            "toDate": to_timestamp
        }
        
        # Sanitize and conditionally add accountIds
        clean_accounts = clean_id_list([self.account_id])
        if clean_accounts:
            json_data["accountIds"] = clean_accounts
        
        # Sanitize and conditionally add siteIds
        clean_sites = clean_id_list(site_ids if site_ids else [self.site_id])
        if clean_sites:
            json_data["siteIds"] = clean_sites
        
        # Use the correct DV runtime init-query endpoint
        url = f'{self.api_url}/web/api/v2.1/dv/init-query'
        return self.post(url, json_data)

    @dag_node('sentinelone__get_powerquery_status', label='powerquery status')
    def get_powerquery_status(self, scan_id: str = '', query_id: str = '') -> dict:
        """Get the current status of a Deep Visibility query."""
        url = f'{self.api_url}/web/api/v2.1/dv/query-status'
        params = {'queryId': query_id}
        return self.fetch(url, params)

    @dag_node('sentinelone__get_powerquery_results', label='powerquery results')
    def get_powerquery_results(self, scan_id: str = '', query_id: str = '') -> dict:
        """Retrieve results from a completed Deep Visibility query."""
        url = f'{self.api_url}/web/api/v2.1/dv/events/pq-ping'
        params = {'queryId': query_id}
        return self.fetch(url, params)

    # ── High-level helpers for AI/SOC agents ──────────────────────────────────

    @dag_node('sentinelone__get_threat_timeline', label='threat timeline')
    def get_threat_timeline(self, scan_id: str = '', threat_id: str = '') -> dict:
        """
        Get the timeline (activity log) of a threat.
        Crucially reveals the custom rule name that triggered the alert.

        Returns dict with:
            rule_name:   Name of the custom rule that triggered (e.g. "URL Phishing Platforms")
            rule_type:   "Custom Rule" | "AI" | "Static" | etc.
            alert_id:    ID of the alert that created the threat
            activities:  List of activity entries with primaryDescription
        """
        url = f'{self.api_url}/web/api/v2.1/threats/{threat_id}/timeline'
        resp = self.fetch(url, params={'limit': 20}) or {}
        items = resp.get('data', [])

        rule_name = None
        rule_type = None
        alert_id  = None
        activities = []

        for item in items:
            primary = item.get('primaryDescription', '')
            activities.append(primary)
            # activityType 3608 = "Alert created for X from Custom Rule: Y"
            # activityType 4107 = "Custom Rule Y automatically marked..."
            if 'Custom Rule' in primary and rule_name is None:
                import re
                m = re.search(r'Custom Rule[:\s]+([^,.]+)', primary)
                if m:
                    raw = m.group(1).strip()
                    # Strip scope suffix e.g. " in Group X in Site Y in Account Z"
                    rule_name = raw.split(' in ')[0].strip()
                    rule_type = 'Custom Rule'
            data = item.get('data', {})
            if not alert_id and data.get('alertid'):
                alert_id = data.get('alertid')
            # Also check initiatedByDescription from the threat itself
            if not rule_name and 'star_active' in str(data):
                rule_type = 'Custom Rule'

        return {
            'rule_name':  rule_name,
            'rule_type':  rule_type,
            'alert_id':   alert_id,
            'activities': activities[:5],  # first 5 entries
        }

    @dag_node('sentinelone__get_threats', label='get threats')
    def get_threats(self, limit=10, sort_by='createdAt', sort_order='desc', filters=None):
        """
        Fetch recent threats from SentinelOne.

        Args:
            limit:      Maximum number of threats to return (default 10).
            sort_by:    Field to sort by (default 'createdAt').
            sort_order: 'asc' or 'desc' (default 'desc').
            filters:    Optional dict of extra query params (e.g. {'incidentStatuses': 'unresolved'}).

        Returns:
            list of dicts with keys: id, threatName, storyline, processUser,
            agentComputerName, createdAt, incidentStatus, mitigationStatus,
            engines, maliciousProcessArguments, originatorProcess.
        """
        import time as _time
        url = f'{self.api_url}/web/api/v2.1/threats'
        params = {'limit': limit, 'sortBy': sort_by, 'sortOrder': sort_order}
        if filters:
            params.update(filters)
        resp = self.fetch(url, params) or {}
        out = []
        for t in resp.get('data', []):
            ti = t.get('threatInfo', {})
            ai = t.get('agentRealtimeInfo', {})
            out.append({
                'id':                        t.get('id'),
                'threatName':                ti.get('threatName'),
                'storyline':                 ti.get('storyline'),
                'processUser':               ti.get('processUser'),
                'agentComputerName':         ai.get('agentComputerName'),
                'createdAt':                 ti.get('createdAt'),
                'incidentStatus':            ti.get('incidentStatus'),
                'mitigationStatus':          ti.get('mitigationStatus'),
                'engines':                   ti.get('engines', []),
                'maliciousProcessArguments': ti.get('maliciousProcessArguments'),
                'originatorProcess':         ti.get('originatorProcess'),
                'initiatedByDescription':    ti.get('initiatedByDescription'),
                'analystVerdict':             ti.get('analystVerdict'),
            })
        return out

    @dag_node('sentinelone__run_dv_query', label='run DV query')
    def run_dv_query(self, query, from_date=None, to_date=None, limit=100, timeout=30):
        """
        Execute a Deep Visibility query and block until results are ready.

        Internally: init-query → poll status → fetch events.
        queryId is never exposed to the caller.

        Args:
            query:     S1QL query string (e.g. 'storyline = "DEADBEEF12345678"').
            from_date: ISO8601 start date (default: 7 days ago).
            to_date:   ISO8601 end date (default: now).
            limit:     Max events to return (default 100).
            timeout:   Max seconds to wait for query to finish (default 30).

        Returns:
            list of event dicts with keys: eventTime, eventType, processName,
            networkUrl, filePath, processCmd, srcProcUser, agentComputerName.
        """
        import time as _time
        from datetime import datetime, timedelta, timezone as _tz

        if not from_date:
            from_date = (datetime.now(_tz.utc) - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        if not to_date:
            to_date = datetime.now(_tz.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')

        result = self.create_powerquery(from_date=from_date, to_date=to_date, query=query, limit=limit)
        query_id = (result or {}).get('data', {}).get('queryId')
        if not query_id:
            return []

        deadline = _time.time() + timeout
        while _time.time() < deadline:
            _time.sleep(2)
            status_data = (self.get_powerquery_status(query_id) or {}).get('data', {})
            if status_data.get('responseState') in ('FINISHED', 'FAILED', 'TIMEOUT'):
                break

        raw = (self.get_powerquery_results(query_id) or {}).get('data', [])
        events = []
        for e in raw:
            events.append({
                'eventTime':   (e.get('eventTime') or '')[:19],
                'eventType':   e.get('eventType', ''),
                'processName': e.get('processName', ''),
                'networkUrl':  e.get('networkUrl', ''),
                'filePath':    e.get('filePath') or e.get('targetFilePath', ''),
                'processCmd':  (e.get('processCmd') or e.get('cmdline', ''))[:300],
                'srcProcUser': e.get('srcProcUser') or e.get('user', ''),
                'computer':    e.get('agentComputerName', ''),
            })
        return events

    @dag_node('sentinelone__get_storyline_events', label='storyline events')
    def get_storyline_events(self, scan_id: str = '', storyline: str = '', event_filter: str | None = None, from_date: str | None = None, to_date: str | None = None, limit: int = 100) -> list[dict]:
        """
        Fetch all Deep Visibility events for a given storyline ID.

        Args:
            storyline:    Hex storyline ID (e.g. '742E582C4AB25E49').
            event_filter: Optional S1QL filter appended with AND
                          (e.g. 'ObjectType = "URL"' or 'event.type = "Process Creation"').
            from_date:    ISO8601 start (default: 7 days ago).
            to_date:      ISO8601 end (default: now).
            limit:        Max events (default 100).

        Returns:
            list of event dicts (same format as run_dv_query).
        """
        query = f'storyline = "{storyline}"'
        if event_filter:
            query += f' AND {event_filter}'
        return self.run_dv_query(query=query, from_date=from_date, to_date=to_date, limit=limit)

    @dag_node('sentinelone__get_unresolved_threats', brand='SentinelOne', label='Get Unresolved Threats')
    def get_unresolved_threats(self, scan_id: str = '', limit: int = 20, hours_back: int = 2) -> list[dict]:
        """
        Fetch unresolved threats from SentinelOne for automated triage.

        Wrapper around get_threats with incidentStatus=unresolved hardcoded.
        Used as the entry point for auto-triage DAGs — resolved threats are
        never returned, acting as the native deduplication mechanism.

        Args:
            limit:      Max threats to return (default 20).
            hours_back: Only threats created in the last N hours (default 2).
                        Set to 0 to disable time filtering.

        Returns:
            list of dicts with keys: id, threatName, storyline, processUser,
            agentComputerName, createdAt, incidentStatus, mitigationStatus.
        """
        filters: dict = {'incidentStatuses': 'unresolved'}
        if hours_back:
            from datetime import datetime, timedelta, timezone as _tz
            since = (datetime.now(_tz.utc) - timedelta(hours=hours_back)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
            filters['createdAt__gt'] = since
        return self.get_threats(limit=limit, filters=filters)

    @dag_node('sentinelone__mark_threat_resolved', brand='SentinelOne', label='Mark Threat Resolved')
    def mark_threat_resolved(
        self,
        scan_id: str = '',
        threat_ids: str = '',
        analyst_verdict: str = 'false_positive',
        note: str = 'Auto-triaged by claw-code-agent DAG',
    ) -> dict:
        """
        Mark one or more threats as resolved in SentinelOne.

        Used as the final step in auto-triage DAGs. Once resolved,
        get_unresolved_threats will never return them again — this
        is the deduplication mechanism (no extra DB needed).

        Args:
            threat_ids:       Comma-separated threat IDs (or a single ID).
            analyst_verdict:  'false_positive' | 'true_positive' | 'suspicious' | 'undefined'.
            note:             Optional note attached to the resolution.

        Returns:
            dict with keys: ok, resolved (list of IDs), analyst_verdict.
        """
        ids = [tid.strip() for tid in str(threat_ids).split(',') if tid.strip()]
        if not ids:
            return {'ok': False, 'error': 'No threat_ids provided'}

        # Set analyst verdict
        self.post(
            f'{self.api_url}/web/api/v2.1/threats/analyst-verdict',
            {'data': {'analystVerdict': analyst_verdict}, 'filter': {'ids': ids}},
        )
        # Resolve incident status (mark-as-resolved 404s on Management API v2.1)
        self.post(
            f'{self.api_url}/web/api/v2.1/threats/incident',
            {'data': {'incidentStatus': 'resolved'}, 'filter': {'ids': ids}},
        )
        return {'ok': True, 'resolved': ids, 'analyst_verdict': analyst_verdict}

    @dag_node('sentinelone__get_dv_event_tabs', label='DV event tabs')
    def get_dv_event_tabs(self, scan_id: str = '', query_id: str = '') -> dict:
        """
        Get event type counts for a Deep Visibility query.
        
        This calls the SentinelOne private user-preferences endpoint that returns 
        event type counts in the format used by the SentinelOne UI.
        
        NOTE: This uses a private/undocumented SentinelOne API endpoint which may
        change without notice in future SentinelOne releases. The public DV API
        does not currently provide accurate event counts, so we use this private
        endpoint to match the SentinelOne UI behavior. Monitor for API changes.
        
        Response format:
        {
            "data": {
                "value": {
                    "tabs": [{
                        "eventTabs": [
                            {"count": 2000, "display": "All Events", "eventType": "events"},
                            {"count": 241, "display": "Processes", "eventType": "process"},
                            ...
                        ]
                    }]
                }
            }
        }
        
        Args:
            query_id: The Deep Visibility query ID
            
        Returns:
            dict: Response from SentinelOne with event type counts
        """
        # Use the private user-preferences endpoint that SentinelOne UI uses
        url = f'{self.api_url}/web/api/v2.1/private/user-preferences/S1-DV'
        params = {'queryId': query_id}
        return self.fetch(url, params)
    
    @dag_node('sentinelone__get_dv_all_events_fields', label='DV events fields')
    def get_dv_all_events_fields(self, scan_id: str = '', query_id: str = '') -> dict:
        """
        Get field definitions for Deep Visibility "All Events" view.
        
        This calls the SentinelOne private /dv/all-events endpoint which returns
        the actual column definitions used by the SentinelOne UI.
        
        NOTE: This uses a private/undocumented SentinelOne API endpoint which may
        change without notice in future SentinelOne releases. This endpoint provides
        the real column schema that matches the SentinelOne console "All Events" view.
        
        The endpoint is called with minimal parameters to get column definitions:
        - limit: 50 (small number to reduce response size, we only need column defs)
        - sortBy: srcProcName (default sort)
        - sortOrder: asc (default order)
        
        Response format:
        {
            "data": {
                "columns": [
                    {"id": "eventType", "title": "Event Type", "type": "string", ...},
                    {"id": "eventTime", "title": "Time", "type": "date", ...},
                    ...
                ]
            }
        }
        
        Args:
            query_id: The Deep Visibility query ID (must be a stream query ID)
            
        Returns:
            dict: Response from SentinelOne with field definitions
        """
        url = f'{self.api_url}/web/api/v2.1/private/dv/all-events'
        params = {
            'limit': 50,
            'sortBy': 'srcProcName',
            'sortOrder': 'asc',
            'queryId': query_id
        }
        return self.fetch(url, params)
    
    @dag_node('sentinelone__get_dv_expand_row', label='DV expand row')
    def get_dv_expand_row(self, scan_id: str = '', query_id: str = '', stream_query_id: str | None = None, row_id: str | None = None, event_id: str | None = None, storyline: str | None = None) -> dict:
        """
        Get expand row details for a Deep Visibility event.
        
        Two-tier approach:
        1. PRIVATE expand-row (if stream_query_id available) - faster, direct access
        2. PUBLIC fallback using /dv/events with filtering - slower but always works
        
        Supports two signatures:
        1. Console signature (preferred): eventId + storyline
        2. Legacy signature (fallback): rowId
        
        NOTE: Public fallback uses pagination with a limit of 5 pages (200 events per page,
        1000 total events searched). Events beyond the first 1000 may not be found.
        This is a reasonable trade-off between performance and coverage for typical use cases.
        
        Args:
            query_id: The Deep Visibility query ID (q... or stream...) (required)
            stream_query_id: The stream query ID (stream...) for private endpoint (optional)
            row_id: The event/row ID (legacy signature)
            event_id: The event ID (console signature)
            storyline: The storyline ID (console signature)
            
        Returns:
            dict: Response with expanded event details in format { "data": {...} }
        """
        # Ensure all IDs are strings to preserve precision
        query_id = str(query_id) if query_id else None
        stream_query_id = str(stream_query_id) if stream_query_id else None
        row_id = str(row_id) if row_id else None
        event_id = str(event_id) if event_id else None
        storyline = str(storyline) if storyline else None
        
        # Validation
        if not query_id:
            raise ValueError("query_id is required")
        
        # Prefer console signature (eventId + storyline) over legacy (rowId)
        use_console_signature = bool(event_id and storyline)
        if not use_console_signature and not row_id:
            raise ValueError("expand-row requires either (eventId + storyline) or rowId")
        
        # STEP 1: Try private expand-row endpoint if we have a stream queryId
        if stream_query_id and stream_query_id.startswith('stream'):
            logger.info(f"S1 expand-row: Attempting private endpoint with stream={stream_query_id}")
            try:
                private_url = f'{self.api_url}/web/api/v2.1/private/dv/events/expand-row'
                
                if use_console_signature:
                    params = {
                        'queryId': stream_query_id,
                        'eventId': event_id,
                        'storyline': storyline
                    }
                    logger.info(f"S1 expand-row private: console signature (eventId={event_id}, storyline={storyline})")
                else:
                    params = {
                        'queryId': stream_query_id,
                        'rowId': row_id
                    }
                    logger.info(f"S1 expand-row private: legacy signature (rowId={row_id})")
                
                logger.debug(f"S1 expand-row private: {private_url} with params {params}")
                response = self.fetch(private_url, params)
                
                # If successful, return immediately
                if response and response.get('data'):
                    logger.info("S1 expand-row: Private endpoint succeeded")
                    return response
                else:
                    logger.warning("S1 expand-row: Private endpoint returned empty data, will try public fallback")
                    
            except Exception as e:
                logger.warning(f"S1 expand-row: Private endpoint failed ({e}), will try public fallback")
        else:
            logger.info(f"S1 expand-row: No valid stream queryId, skipping private endpoint")
        
        # STEP 2: Public fallback - use /dv/events with filtering
        logger.info(f"S1 expand-row: Using public fallback with query_id={query_id}")
        
        try:
            public_url = f'{self.api_url}/web/api/v2.1/dv/events'
            
            # Search for event using pagination
            if use_console_signature:
                # Filter by eventId AND storyline for better precision
                logger.info(f"S1 expand-row public: Searching for eventId={event_id}, storyline={storyline}")
                
                def match_func(event):
                    """Check if event matches the target eventId and storyline."""
                    # First check if storyline matches (more specific)
                    event_storyline = str(event.get('storyline', '')) or str(event.get('storylineId', ''))
                    storyline_matches = (event_storyline == storyline) if storyline else True
                    
                    if not storyline_matches:
                        return False
                    
                    # Then check if any ID field matches
                    # Check dvEventId first (preferred)
                    if str(event.get('dvEventId', '')) == event_id:
                        return True
                    # Check eventId
                    if str(event.get('eventId', '')) == event_id:
                        return True
                    # Check id field
                    if str(event.get('id', '')) == event_id:
                        return True
                    return False
                
                id_desc = f"eventId {event_id}"
            else:
                # Legacy signature - rowId (which is usually the eventId)
                logger.info(f"S1 expand-row public: Searching for rowId={row_id}")
                
                def match_func(event):
                    """Check if event matches the target rowId."""
                    # Check multiple fields
                    if str(event.get('dvEventId', '')) == row_id:
                        return True
                    if str(event.get('eventId', '')) == row_id:
                        return True
                    if str(event.get('id', '')) == row_id:
                        return True
                    return False
                
                id_desc = f"rowId {row_id}"
            
            # Search with pagination
            matching_event = self._search_events_paginated(
                public_url, query_id, match_func, id_desc
            )
            
            if matching_event:
                return {"data": matching_event}
            else:
                return {
                    "data": [],
                    "error": f"Event with {id_desc} not found (searched up to 3000 events)"
                }
                    
        except Exception as e:
            logger.error(f"S1 expand-row public fallback failed: {e}", exc_info=True)
            raise ValueError(f"Both private and public expand methods failed: {str(e)}")
    
    def _search_events_paginated(self, url, query_id, match_func, id_desc):
        """
        Search for a specific event using cursor-based pagination.
        
        Uses smarter stopping criteria:
        - Increased page limit for better coverage
        - Time-based stopping if event timestamps suggest we've passed the target
        
        Args:
            url: The API endpoint URL
            query_id: The query ID to search within
            match_func: Function that takes an event dict and returns True if it matches
            id_desc: Description of the ID being searched (for logging)
            
        Returns:
            dict: The matching event, or None if not found
        """
        max_pages = 15  # Increased from 5 to 15 (3000 events) for better coverage
        page = 0
        cursor = None
        
        while page < max_pages:
            params = {
                'queryId': query_id,
                'limit': 200  # Reasonable page size
            }
            
            if cursor:
                params['cursor'] = cursor
            
            response = self.fetch(url, params)
            
            if not response or not response.get('data'):
                logger.debug(f"S1 pagination: No more data on page {page + 1}")
                break
            
            events = response.get('data', [])
            
            # Search for matching event in this page
            for event in events:
                if match_func(event):
                    logger.info(f"S1 pagination: Found matching event ({id_desc}) on page {page + 1}")
                    return event
            
            # Get next cursor for pagination
            pagination = response.get('pagination', {})
            cursor = pagination.get('nextCursor')
            
            if not cursor:
                logger.debug(f"S1 pagination: No more pages after page {page + 1}")
                break  # No more pages
            
            page += 1
            logger.debug(f"S1 pagination: Checked page {page}, moving to next")
        
        logger.info(f"S1 pagination: Event ({id_desc}) not found after searching {page + 1} page(s)")
        return None


    # Asynchronous create_s1_rule method
    async def async_create_s1_rule(self, title, description, s1ql_query):
        json_data = {
            'data': {
                'name': title,
                'description': description,
                'severity': 'Low',
                'expirationMode': 'Permanent',
                'expiration': None,
                's1ql': s1ql_query,
                'queryType': 'events',
                'queryLang': '1.0',
                'treatAsThreat': 'Suspicious',
                'networkQuarantine': False,
                'status': 'Active',
            },
            'filter': {
                'accountIds': self.account_id,
            },
        }
        url = f'{self.api_url}/web/api/v2.1/cloud-detection/rules'
        return await self.async_post(url, json_data)

    @dag_node('sentinelone__create_rule', label='create rule')
    def create_rule(self, scan_id: str = '', title: str = '', description: str = '', severity: str = '', query: str = '', account_id: str = '', network_quarantine: bool = False, treat_as: str = '', status: str = '') -> dict:
        """Create a cloud detection rule in SentinelOne."""
        json_data = {
            'data': {
                'name': title,
                'description': description,
                'severity': severity,
                'expirationMode': 'Permanent',
                'expiration': None,
                's1ql': query,
                'queryType': 'events',
                'queryLang': '1.0',
                'treatAsThreat': treat_as,
                'networkQuarantine': network_quarantine,
                'status': status,
            },
            'filter': {
                'accountIds': account_id,
            },
        }
        url = f'{self.api_url}/web/api/v2.1/cloud-detection/rules'
        return self.post(url, json_data)

    # Asynchronous block_ip_addresses method
    async def async_block_ip_addresses(self, rule_name, ip_addresses):
        ip_list = '", "'.join(ip_addresses)
        s1ql_query = f'SrcIP in ("{ip_list}") OR DstIP in ("{ip_list}")'

        json_data = {
            'data': {
                'name': rule_name,
                'description': '',
                'severity': 'Critical',
                'expirationMode': 'Permanent',
                'expiration': None,
                's1ql': s1ql_query,
                'queryType': 'events',
                'queryLang': '1.0',
                'treatAsThreat': 'Malicious',
                'networkQuarantine': True,
                'status': 'Active',
            },
            'filter': {
                'accountIds': self.account_id,
            },
        }
        url = f'{self.api_url}/web/api/v2.1/cloud-detection/rules'
        return await self.async_post(url, json_data)

    @dag_node('sentinelone__block_ip_addresses', label='block IPs')
    def block_ip_addresses(self, scan_id: str = '', rule_name: str = '', ip_addresses: list | None = None) -> dict:
        """Block IP addresses by creating a cloud detection rule with network quarantine."""
        ip_list = '", "'.join(ip_addresses)
        s1ql_query = f'SrcIP in ("{ip_list}") OR DstIP in ("{ip_list}")'

        json_data = {
            'data': {
                'name': rule_name,
                'description': '',
                'severity': 'Critical',
                'expirationMode': 'Permanent',
                'expiration': None,
                's1ql': s1ql_query,
                'queryType': 'events',
                'queryLang': '1.0',
                'treatAsThreat': 'Malicious',
                'networkQuarantine': True,
                'status': 'Active',
            },
            'filter': {
                'accountIds': self.account_id,
            },
        }
        url = f'{self.api_url}/web/api/v2.1/cloud-detection/rules'
        return self.post(url, json_data)

    # Asynchronous create_firewall_rule method
    async def async_create_firewall_rule(self, action, threat_name, addresses, site):
        remote_hosts = [{'type': 'addresses', 'values': [address]} for address in addresses]

        json_data = {
            'data': {
                'name': action + " " + threat_name,
                'osTypes': ['windows', 'macos', 'linux'],
                'tagIds': [],
                'action': action,
                'status': 'Enabled',
                'description': None,
                'protocol': '',
                'application': {
                    'type': 'any',
                    'values': [],
                },
                'direction': 'any',
                'localHost': {
                    'type': 'any',
                    'values': [],
                },
                'localPort': {
                    'type': 'any',
                    'values': [],
                },
                'remotePort': {
                    'type': 'any',
                    'values': [],
                },
                'remoteHosts': remote_hosts,
                'location': {
                    'type': 'all',
                    'values': None,
                },
            }
        }
        
        if site:
            json_data['filter'] = {'siteIds': site}
        else:
            json_data['filter'] = {'accountIds': self.account_id}

        url = f'{self.api_url}/web/api/v2.1/firewall-control'
        return await self.async_post(url, json_data)

    @dag_node('sentinelone__create_firewall_rule', label='firewall rule')
    def create_firewall_rule(self, scan_id: str = '', action: str = '', threat_name: str = '', addresses: list | None = None, site: str | None = None) -> dict:
        """Create a firewall rule to block/allow specific network addresses."""
        remote_hosts = [{'type': 'addresses', 'values': [address]} for address in addresses]

        json_data = {
            'data': {
                'name': action + " " + threat_name,
                'osTypes': ['windows', 'macos', 'linux'],
                'tagIds': [],
                'action': action,
                'status': 'Enabled',
                'description': None,
                'protocol': '',
                'application': {
                    'type': 'any',
                    'values': [],
                },
                'direction': 'any',
                'localHost': {
                    'type': 'any',
                    'values': [],
                },
                'localPort': {
                    'type': 'any',
                    'values': [],
                },
                'remotePort': {
                    'type': 'any',
                    'values': [],
                },
                'remoteHosts': remote_hosts,
                'location': {
                    'type': 'all',
                    'values': None,
                },
            }
        }
        
        if site:
            json_data['filter'] = {'siteIds': site}
        else:
            json_data['filter'] = {'accountIds': self.account_id}

        url = f'{self.api_url}/web/api/v2.1/firewall-control'
        return self.post(url, json_data)

    # Asynchronous create_restriction method
    async def async_create_restriction(self, restriction_type, description, os_type, value):
        json_data = {
            'data': {
                'type': restriction_type,
                'description': description,
                'osType': os_type,
                'value': value
            },
            'filter': {
                'accountIds': self.account_id,
            },
        }
        url = f'{self.api_url}/web/api/v2.1/restrictions'
        return await self.async_post(url, json_data)

    @dag_node('sentinelone__create_restriction', label='create restriction')
    def create_restriction(self, scan_id: str = '', restriction_type: str = '', description: str = '', os_type: str = '', value: str = '') -> dict:
        """Create a restriction (blocklist/allowlist entry) in SentinelOne."""
        json_data = {
            'data': {
                'type': restriction_type,
                'description': description,
                'osType': os_type,
                'value': value
            },
            'filter': {
                'accountIds': self.account_id,
            },
        }
        url = f'{self.api_url}/web/api/v2.1/restrictions'
        return self.post(url, json_data)
    
    @dag_node('sentinelone__check_port_scans', label='check port scans')
    def check_port_scans(
        self,
        scan_id: str = '',
        site_ids: list | None = None,
        site_name_filter: str = '',
        exclude_dst_ip: str = '',
    ) -> dict:
        """Detect port scan activity using PowerQuery over recent network events."""
        to_date = datetime.now() - timedelta(minutes=10)
        from_date = to_date - timedelta(minutes=20)

        query_parts = [
            "event.category = 'ip' AND src.ip.address != null",
        ]
        if site_name_filter:
            query_parts.append(f"site.name ContainsCIS '{site_name_filter}'")
        if exclude_dst_ip:
            query_parts.append(f"dst.ip.address != '{exclude_dst_ip}'")
        query_parts.append("dst.ip.address matches '((192\\.168\\..)).'")
        query = (
            " ".join(query_parts)
            + " | group SuccessfulConnectionsPerIP = count(dst.port.number) by AttackerIPAddress = src.ip.address, DstIPAddress = dst.ip.address, DstPortNumber = dst.port.number, EventTime = event.time\n"
            "| group DistinctPorts = count(AttackerIPAddress), TotalSuccessfulConnections = sum(SuccessfulConnectionsPerIP) by AttackerIPAddress, EventTime, DstIPAddress\n"
            "| columns AttackerIPAddress, TotalSuccessfulConnections, DistinctPorts, DstIPAddress\n"
            "| filter DistinctPorts >= 3\n"
        )

        scoped_site_ids = clean_id_list(site_ids if site_ids is not None else self._configured_site_ids())

        response = self.create_powerquery(
            from_date=from_date,
            to_date=to_date,
            query=query,
            limit=20000,
            site_ids=scoped_site_ids or None,
        )

        alerts = []

        # Check the response
        if response['data']['status'] == "FINISHED":
            result_data = response['data']['data']

            # Check if there are any results
            if len(result_data) > 0:
                for entry in result_data:
                    attacker_ip = entry[0]
                    ports_scanned = int(entry[1])
                    private_ip_ports_scanned = entry[2]
                    victim_ip = entry[3]

                    # Structure the alert info
                    alert_info = {
                        'alertId': f'port_scan_{attacker_ip}',
                        'description': 'Port scan activity detected',
                        'siteName': site_name_filter or '',
                    }

                    agent_detection_info = {
                        'name': f'IP Atacante: {attacker_ip} → {victim_ip} ({ports_scanned} puertos simultaneos)',
                        'osName': site_name_filter or '',
                        'machineType': 'Red',
                    }

                    rule_info = {
                        'name': 'Escaneo de Puertos',
                        'severity': 'High',  # Adjust severity based on conditions if needed
                    }

                    source_process_info = {
                        'TotalSuccessfulConnections': ports_scanned,
                        'PrivateIPPortsScanned': private_ip_ports_scanned,
                    }

                    # Construct the alert dictionary
                    alert = {
                        'alertInfo': alert_info,
                        'agentDetectionInfo': agent_detection_info,
                        'ruleInfo': rule_info,
                        'sourceProcessInfo': source_process_info
                    }

                    # Append alert to the list of alerts
                    alerts.append(alert)

            else:
                print("No port scan activity detected.")
        else:
            print("Query is still processing or failed.")

        return {'data': alerts}

    # Synchronous alert_handler method
    def alert_handler(self):
        def decorator(handler):
            handler_dict = {
                'handler': handler,
            }
            self.alert_handlers.append(handler_dict)
            return handler
        return decorator

    # Asynchronous handle_alerts method
    async def async_handle_alerts(self):
        alert_params = {"sortBy": "alertInfoCreatedAt", "sortOrder": "desc"}
        site_ids = self._configured_site_ids()
        if site_ids:
            alert_params["siteIds"] = site_ids
        while True:
            try:
                alerts = await self.async_get_alerts(**alert_params)
                if alerts.get('data', None):
                    new_alerts = [alert for alert in alerts['data'] if alert['alertInfo']['alertId'] not in self.processed_alert_ids]
                    for alert in new_alerts:
                        await self.process_alert(alert)
                        self.processed_alert_ids.add(alert['alertInfo']['alertId'])
                        self.last_alert_id = alert['alertInfo']['alertId']
            except Exception as e:
                print(f"Error while fetching or processing alerts: {e}")
            print('Checking new alerts...')
            await asyncio.sleep(30)

    # Synchronous handle_alerts method
    def handle_alerts(self):
        alert_params = {"sortBy": "alertInfoCreatedAt", "sortOrder": "desc"}
        site_ids = self._configured_site_ids()
        if site_ids:
            alert_params["siteIds"] = site_ids
        while True:

            # Alertes de PowerQuery

            try:
                port_scan_alerts = self.check_port_scans()
                if port_scan_alerts.get('data', None):
                    new_alerts = [alert for alert in port_scan_alerts['data'] if alert['alertInfo']['alertId'] not in self.processed_alert_ids]
                    for alert in new_alerts:
                        self.process_alert_sync(alert)
                        self.processed_alert_ids.add(alert['alertInfo']['alertId'])
            except Exception as e:
                print(f"Error while fetching or processing PowerQuery: {e}")
            
            # Alertes normals

            try:
                alerts = self.get_alerts(**alert_params)
                print(alerts)
                if alerts.get('data', None):
                    new_alerts = [alert for alert in alerts['data'] if alert['alertInfo']['alertId'] not in self.processed_alert_ids]
                    for alert in new_alerts:
                        self.process_alert_sync(alert)
                        self.processed_alert_ids.add(alert['alertInfo']['alertId'])
            except Exception as e:
                print(f"Error while fetching or processing alerts: {e}")

            print('Checking new alerts...')
            time.sleep(30)

    # Asynchronous process_alert method
    async def process_alert(self, alert):
        for handler_dict in self.alert_handlers:
            handler = handler_dict['handler']
            filters = handler_dict['filters']
            if self.check_filters(alert, filters):
                await handler(alert)

    # Synchronous process_alert method
    def process_alert_sync(self, alert):
        for handler_dict in self.alert_handlers:
            handler = handler_dict['handler']
            handler(alert)

    # Check filters method
    def check_filters(self, alert, filters):
        for key, value in filters.items():
            if key not in alert['alertInfo'] or alert['alertInfo'][key] != value:
                return False
        return True

    # Asynchronous infinity_polling method
    async def async_infinity_polling(self, func, interval=10, **query_params):
        decorated_func = self.alert_handler(**query_params)(func)
        while True:
            try:
                await decorated_func()
            except Exception as e:
                print(f'Error: {e}')
            await asyncio.sleep(interval)


    # Synchronous infinity_polling method
    def infinity_polling(self, func, interval=10, **query_params):
        decorated_func = self.alert_handler(**query_params)(func)
        while True:
            try:
                decorated_func()
            except Exception as e:
                print(f'Error: {e}')
            time.sleep(interval)
    
    @dag_node('sentinelone__get_protected_devices', label='protected devices')
    def get_protected_devices(self, scan_id: str = '', account_id: str = '', site_id: str = '') -> list[dict]:
        """Retrieve protected endpoints (agents) from SentinelOne."""
        url = f'{self.api_url}/web/api/v2.1/agents'
        params = {
            "accountIds": account_id,
            "siteIds": site_id,
            "limit": 1000
        }
        data = self.fetch(url, params)
        
        results = []
        for d in data.get("data", []):
            # Extract network information safely
            network_interfaces = d.get("networkInterfaces", [])
            mac_address = "N/A"
            ip_address = "N/A"
            
            if network_interfaces and len(network_interfaces) > 0:
                mac_address = network_interfaces[0].get("physical", "N/A")
                ip_address = network_interfaces[0].get("inet", "N/A")
            
            results.append({
                "id": d.get("id"),
                "name": d.get("computerName"),
                "ip": ip_address,
                "os": d.get("osName"),
                "site_id": d.get("siteId"),
                "group_id": d.get("groupId"),
                "group_name": d.get("groupName", "Desconocido"),
                "mac_address": mac_address,
                "manufacturer": d.get("manufacturer", "N/A"),
                "is_protected": True,
                "network_status": d.get("networkStatus", "unknown"),
                "is_isolated": d.get("networkStatus") == "disconnected"
            })
        
        return results
        
    @dag_node('sentinelone__get_unprotected_devices', label='unprotected devices')
    def get_unprotected_devices(self, scan_id: str = '', account_id: str = '', site_id: str = '') -> list[dict]:
        """Retrieve unprotected endpoints (rogues) from SentinelOne."""
        url = f'{self.api_url}/web/api/v2.1/rogues/table-view'
        params = {
            "accountIds": account_id,
            "siteIds": site_id,
            "limit": 1000
        }
        data = self.fetch(url, params)
        
        results = []
        for d in data.get("data", []):
            # Extract hostname safely
            hostnames = d.get("hostnames", [])
            name = "N/A"
            if isinstance(hostnames, list) and len(hostnames) > 0:
                name = hostnames[0]
            
            results.append({
                "id": d.get("id"),
                "name": name,
                "ip": d.get("localIp") or d.get("externalIp", "N/A"),
                "os": d.get("osName", "N/A"),
                "mac_address": d.get("macAddress", "N/A"),
                "manufacturer": d.get("manufacturer", "N/A"),
                "is_protected": False
            })
        
        return results
    
    @dag_node('sentinelone__disconnect_agents', label='disconnect agents')
    def disconnect_agents(self, scan_id: str = '', agent_ids: list | None = None, site_id: str = '') -> dict:
        """
        Disconnect (isolate) agents from network using SentinelOne API v2.1.
        
        Args:
            agent_ids: List of agent IDs or single agent ID
            site_id: Site ID for filtering
            
        Returns:
            dict: Response from SentinelOne with affected count
        """
        if not isinstance(agent_ids, list):
            agent_ids = [agent_ids]
        
        url = f'{self.api_url}/web/api/v2.1/agents/actions/disconnect'
        payload = {
            "filter": {
                "siteIds": [site_id],
                "ids": agent_ids
            }
        }
        
        try:
            response = self.post(url, payload)
            return {
                "success": True,
                "affected": response.get("data", {}).get("affected", 0),
                "response": response
            }
        except Exception as e:
            logging.error(f"Error disconnecting agents: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    @dag_node('sentinelone__connect_agents', label='connect agents')
    def connect_agents(self, scan_id: str = '', agent_ids: list | None = None, site_id: str = '') -> dict:
        """
        Reconnect (de-isolate) agents to network using SentinelOne API v2.1.
        
        Args:
            agent_ids: List of agent IDs or single agent ID
            site_id: Site ID for filtering
            
        Returns:
            dict: Response from SentinelOne with affected count
        """
        if not isinstance(agent_ids, list):
            agent_ids = [agent_ids]
        
        url = f'{self.api_url}/web/api/v2.1/agents/actions/connect'
        payload = {
            "filter": {
                "siteIds": [site_id],
                "ids": agent_ids
            }
        }
        
        try:
            response = self.post(url, payload)
            return {
                "success": True,
                "affected": response.get("data", {}).get("affected", 0),
                "response": response
            }
        except Exception as e:
            logging.error(f"Error connecting agents: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    @dag_node('sentinelone__get_last_logged_in_user', label='last logged user')
    def get_last_logged_in_user(self, scan_id: str = '', site_id: str = '') -> str | None:
        """
        Get the most recently logged in user for a site.
        
        Args:
            site_id: Site ID to query
            
        Returns:
            str: Username of last logged in user, or None
        """
        url = f'{self.api_url}/web/api/v2.1/agents'
        params = {
            "siteIds": site_id,
            "limit": 1000  # Get more agents to find the most recent
        }
        
        try:
            data = self.fetch(url, params)
            agents = data.get("data", [])
            if agents:
                # Find the agent with the most recent lastActiveDate
                most_recent_agent = max(agents, key=lambda x: x.get("lastActiveDate", ""), default=None)
                if most_recent_agent:
                    return most_recent_agent.get("lastLoggedInUserName")
            return None
        except Exception as e:
            logging.error(f"Error getting last logged in user: {e}")
            return None
    
    @dag_node('sentinelone__get_agents_by_user', label='agents by user')
    def get_agents_by_user(self, scan_id: str = '', site_id: str = '', username: str = '') -> list:
        """
        Get all agents where a specific user is logged in.
        
        Args:
            site_id: Site ID to filter
            username: Username to search for
            
        Returns:
            list: List of agent IDs for the user
        """
        url = f'{self.api_url}/web/api/v2.1/agents'
        params = {
            "siteIds": site_id,
            "lastLoggedInUserName": username,
            "limit": 1000
        }
        
        try:
            data = self.fetch(url, params)
            agents = data.get("data", [])
            return [agent.get("id") for agent in agents if agent.get("id")]
        except Exception as e:
            logging.error(f"Error getting agents by user: {e}")
            return []

    @dag_node('sentinelone__get_installed_applications_cves', label='app CVEs')
    def get_installed_applications_cves(self, scan_id: str = '', account_id: str = '', site_id: str = '', cursor: str | None = None, limit: int = 1000) -> dict:
        """
        Fetch CVEs from installed applications on endpoints in SentinelOne.
        
        This method retrieves vulnerability data (CVEs) from the SentinelOne API
        endpoint /installed-applications/cves, with support for pagination.
        
        Args:
            account_id (str): Account ID to filter results
            site_id (str): Site ID to filter results
            cursor (str, optional): Pagination cursor from previous response (nextCursor)
            limit (int, optional): Number of results per page (default: 1000)
            
        Returns:
            dict: Response from SentinelOne API containing:
                - data: List of CVE objects with fields:
                    - cveId: CVE identifier (e.g., "CVE-2021-40709")
                    - riskLevel: Risk level (critical, high, medium, low)
                    - score: CVSS score (float)
                    - description: CVE description
                    - publishedAt: Publication date
                    - link: Link to CVE details
                    - createdAt: Creation timestamp
                    - updatedAt: Update timestamp
                - pagination: Pagination information with nextCursor and totalItems
                
        Example:
            >>> helper = SentinelOneHelper(api_key)
            >>> result = helper.get_installed_applications_cves("123", "456")
            >>> cves = result["data"]
            >>> next_cursor = result["pagination"]["nextCursor"]
        """
        url = f"{self.api_url}/web/api/v2.1/installed-applications/cves"
        params = {
            "accountIds": account_id,
            "siteIds": site_id,
            "limit": limit
        }
        
        # Add cursor for pagination if provided
        if cursor:
            params["cursor"] = cursor
        
        try:
            response = self.fetch(url, params)
            logging.info(f"Fetched {len(response.get('data', []))} CVEs from SentinelOne")
            return response
        except Exception as e:
            logging.error(f"Error fetching CVEs from SentinelOne: {e}")
            return {"data": [], "pagination": {}}

    @dag_node('sentinelone__collect_cves_by_endpoint', brand='SentinelOne', label='Collect CVEs by Endpoint')
    def collect_cves_by_endpoint(
        self,
        site_id: str,
        agents: list = None,
        agents_from: str = '',
        ninja_crosscheck: bool = True,
    ) -> dict:
        """
        Collect all CVEs grouped by CVE ID with per-endpoint tracking for a site.

        Iterates every agent in the site, fetches its vulnerable apps, then fetches
        CVEs for each app. Returns a flat dict ready for VulnCheck enrichment.

        Args:
            site_id:        SentinelOne site ID (used for apps API filter).
            agents:         List of agent dicts (from sentinelone__get_agents output).
            agents_from:    DAG ref alias (unused at runtime — for canvas wiring only).
            ninja_crosscheck: If True, query ES endpoints index to cross-check app
                              presence in NinjaOne inventory (confidence field).

        Returns:
            {
              "cves_by_id": {
                "<CVE-ID>": {
                  "cve_data": {...},                    # base S1 fields
                  "affected_endpoint_apps": [...]       # one entry per (endpoint, app)
                }
              },
              "stats": {agents, applications, cves_found, unique_cves}
            }
        """
        import hashlib, re, threading
        from collections import defaultdict
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from datetime import datetime

        # ── helpers (same logic as tasks_enhanced_vulnerabilities) ──────────
        def _norm_name(n):
            if not n:
                return ''
            n = n.lower()
            n = re.sub(r'\s*(\(64[- ]?bit\)|\(32[- ]?bit\)|\(x64\)|\(x86\))', '', n)
            n = re.sub(r'[®™©]', '', n)
            return re.sub(r'\s+', ' ', n).strip()

        def _norm_ver(v):
            return (v or '').strip().lstrip('vV')

        def _split_name_ver(name, version):
            if version or not name:
                return name, version
            name_s = re.sub(r'\s*\((?:x64|x86|32[- ]?bit|64[- ]?bit)\)\s*$', '', name).strip()
            m = re.search(r'\s+(\d+(?:\.\d+){1,5})\s*$', name_s)
            if m:
                return name_s[:m.start()].strip(), m.group(1)
            return name, version

        def _app_hash(name, version):
            raw = f"{_norm_name(name)}::{_norm_ver(version)}".encode()
            return hashlib.sha256(raw).hexdigest()[:16]

        def _confidence(app_name, app_version, ninja_idx):
            if not ninja_idx:
                return 'unverified'
            vlist = ninja_idx.get(_norm_name(app_name))
            if not vlist:
                return 'low'
            return 'high' if _norm_ver(app_version) in vlist else 'medium'

        # ── Ninja app index lookup from ES (optional) ────────────────────────
        ninja_cache: dict = {}
        ninja_lock = threading.Lock()

        def _ninja_index_for_agent(agent_id, agent_name):
            with ninja_lock:
                if agent_id in ninja_cache:
                    return ninja_cache[agent_id]
            idx = {}
            if ninja_crosscheck:
                try:
                    from app.helpers.elastic_helper import create_elastic_client
                    es = create_elastic_client()
                    if es:
                        should = [
                            {'term': {'edr.sentinelone.agent_id': agent_id}},
                            {'term': {'edr.sentinelone.agent_id.keyword': agent_id}},
                        ]
                        if agent_name and agent_name != 'Unknown':
                            should += [
                                {'term': {'systemName.keyword': agent_name}},
                                {'match': {'systemName': {'query': agent_name, 'operator': 'and'}}},
                            ]
                        resp = es.search(index='endpoints', body={
                            'size': 1,
                            '_source': ['applications'],
                            'query': {'bool': {'should': should, 'minimum_should_match': 1}}
                        })
                        hits = resp.get('hits', {}).get('hits', [])
                        if hits:
                            apps = hits[0].get('_source', {}).get('applications') or []
                            for app in apps:
                                name = _norm_name(app.get('name') or app.get('productName', ''))
                                ver  = _norm_ver(app.get('version') or app.get('productVersion', ''))
                                if name:
                                    idx.setdefault(name, []).append(ver)
                except Exception as e:
                    logger.debug(f"ninja_crosscheck ES lookup failed for {agent_name}: {e}")
            with ninja_lock:
                ninja_cache[agent_id] = idx
            return idx

        # ── Main collection ──────────────────────────────────────────────────
        agents = agents or []
        cves_by_id = defaultdict(lambda: {'cve_data': None, 'affected_endpoint_apps': []})
        cves_lock = threading.Lock()
        stats = {'agents': len(agents), 'applications': 0, 'cves_found': 0, 'unique_cves': 0}
        stats_lock = threading.Lock()

        def _process_agent(agent):
            agent_id   = agent.get('id')
            agent_name = agent.get('computerName', 'Unknown')
            ninja_idx  = _ninja_index_for_agent(agent_id, agent_name)
            local_apps, local_cves = 0, 0

            try:
                apps_resp = self.fetch(
                    f"{self.api_url}/web/api/v2.1/application-management/risks/applications",
                    params={'siteIds': site_id, 'endpointName__contains': agent_name}
                )
                apps = apps_resp.get('data', [])
                local_apps = len(apps)

                for app in apps:
                    app_id  = app.get('applicationId') or app.get('id')
                    a_name  = app.get('name', 'Unknown')
                    a_ver   = app.get('version', '')
                    a_vendor = app.get('vendor', '')
                    a_name, a_ver = _split_name_ver(a_name, a_ver)
                    if not app_id:
                        continue
                    try:
                        cves_resp = self.fetch(
                            f"{self.api_url}/web/api/v2.1/application-management/risks/cves",
                            params={'applicationIds': app_id, 'limit': 100}
                        )
                        cves = cves_resp.get('data', [])
                        local_cves += len(cves)

                        for cve in cves:
                            cve_id = cve.get('cveId')
                            if not cve_id or cve_id == 'N/A':
                                continue
                            confidence = _confidence(a_name, a_ver, ninja_idx)
                            ep_entry = {
                                'endpoint_id':           agent_id,
                                'endpoint_name':         agent_name,
                                'endpoint_os_type':      agent.get('osType', '').lower(),
                                'endpoint_os_name':      agent.get('osName', ''),
                                'endpoint_network_status': agent.get('networkStatus', ''),
                                'endpoint_ip_address':   (
                                    agent.get('externalIp')
                                    or (agent.get('networkInterfaces') or [{}])[0].get('inet', '')
                                ),
                                'endpoint_last_active':  agent.get('lastActiveDate'),
                                'endpoint_site_id':      site_id,
                                'endpoint_group_id':     agent.get('groupId'),
                                'endpoint_group_name':   agent.get('groupName', ''),
                                'application_name':      a_name,
                                'application_version':   a_ver,
                                'application_vendor':    a_vendor,
                                'application_hash':      _app_hash(a_name, a_ver),
                                'confidence':            confidence,
                            }
                            with cves_lock:
                                entry = cves_by_id[cve_id]
                                if entry['cve_data'] is None:
                                    entry['cve_data'] = {
                                        'cveId':       cve_id,
                                        'riskLevel':   cve.get('riskLevel', 'unknown'),
                                        'score':       float(cve.get('score', 0.0)),
                                        'description': cve.get('description', ''),
                                        'publishedAt': cve.get('publishedAt'),
                                        'link':        cve.get('link') or f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
                                        'timestamp':   datetime.utcnow().isoformat() + 'Z',
                                    }
                                # dedup same endpoint+app+version
                                if not any(
                                    e['endpoint_id'] == agent_id
                                    and e['application_name'] == a_name
                                    and e['application_version'] == a_ver
                                    for e in entry['affected_endpoint_apps']
                                ):
                                    entry['affected_endpoint_apps'].append(ep_entry)
                    except Exception as cve_err:
                        logger.warning(f"CVE fetch failed for app {a_name} on {agent_name}: {cve_err}")

            except Exception as agent_err:
                logger.warning(f"collect_cves: agent {agent_name} error: {agent_err}")

            with stats_lock:
                stats['applications'] += local_apps
                stats['cves_found']   += local_cves

        max_workers = min(4, max(1, len(agents)))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(_process_agent, a): a.get('computerName', '?') for a in agents}
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as e:
                    logger.error(f"collect_cves worker error: {e}")

        stats['unique_cves'] = len(cves_by_id)
        return {'cves_by_id': dict(cves_by_id), 'stats': stats}


# ─────────────────────────────────────────────────────────────────────────────
# SentinelDataLakeHelper — XDR Data Lake (fast log search, S1QL v2)
# ─────────────────────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────────────────
# SentinelDataLakeHelper — XDR Data Lake (AI SIEM Event Search, S1QL v2)
# ─────────────────────────────────────────────────────────────────────────────

class SentinelDataLakeHelper(DagNotifier, BaseHelper):
    """
    SentinelOne XDR Data Lake client — AI SIEM Event Search (S1QL v2).

    Auth:   Bearer {xdr_token}  (auto-loaded from Azure Key Vault)
    URL:    https://xdr.eu1.sentinelone.net/api/query

    Primary API: xdr.query(event_type, **filters)

    Supported event_type values (from official S1QL docs):
        PROCESS_CREATION      — tgt.process.* fields
        COMMAND_SCRIPT        — cmdScript.* fields
        CROSS_PROCESS         — event.crossProcess.* fields
        DNS                   — event.dns.* fields
        DRIVER                — driver.* fields
        FILE                  — tgt.file.* (creation/modification/deletion/rename)
        INDICATOR             — indicator event types
        LOGIN / LOGOUT        — event.login.* fields
        MODULE_LOAD           — module.* fields
        NETWORK               — dst.ip.*, dst.port.*, networkConnection.* fields
        REGISTRY              — registry.* fields
        SCHEDULED_TASK        — scheduledTask.* fields
        URL                   — networkConnection.url.address field

    Common filter kwargs (all optional):
        endpoint      str   — endpoint.name
        os            str   — endpoint.os  (windows|linux|macos|android|ios)
        site          str   — site.name
        src_process   str   — src.process.name contains
        src_user      str   — src.process.user contains
        src_cmdline   str   — src.process.cmdline contains
        sha256        str   — hash filter (varies by event type)
        storyline_id  str   — src.process.storyline.id exact
        extra         str   — raw S1QL v2 fragment appended with AND

    Time range (pick one):
        hours         int   — last N hours (default: 24)
        start / end   str|datetime
    """

    CREDENTIAL          = ("S1_XDR_TOKEN",)
    CREDENTIAL_KWARGS_MAP = {"S1_XDR_TOKEN": "xdr_token"}
    CONNECTION      = "EDRConnection?service=sentinelone"

    @classmethod
    def node_prefix(cls) -> str:
        return "sentinelone_dataset"

    BASE_URL = 'https://xdr.{region}.sentinelone.net/api/query'

    # ── event_type → (event.type filter string, specific field mapping) ────────
    _EVENT_MAP = {
        # ── Processes ──────────────────────────────────────────────────────────
        'PROCESS_CREATION': {
            'filter': 'event.type = "Process Creation"',
            'fields': {
                'image':        ('tgt.process.image.path', 'endswith:anycase'),
                'cmdline':      ('tgt.process.cmdline',    'contains:anycase'),
                'process_name': ('tgt.process.name',       'contains:anycase'),
                'pid':          ('tgt.process.pid',        '='),
                'sha256':       ('tgt.process.image.sha256','='),
                'integrity':    ('tgt.process.integrityLevel', '='),
                'signed_status':('tgt.process.signedStatus',   '='),
                'publisher':    ('tgt.process.publisher',  'contains:anycase'),
            }
        },
        'PROCESS_TERMINATION': {
            'filter': 'event.type = "Process Termination"',
            'fields': {
                'image':        ('tgt.process.image.path', 'endswith:anycase'),
                'cmdline':      ('tgt.process.cmdline',    'contains:anycase'),
                'process_name': ('tgt.process.name',       'contains:anycase'),
            }
        },
        # ── Command Scripts ────────────────────────────────────────────────────
        'COMMAND_SCRIPT': {
            'filter': 'event.type = "Command Script"',
            'fields': {
                'app':          ('cmdScript.applicationName', 'contains:anycase'),
                'content':      ('cmdScript.content',         'contains:anycase'),
                'sha256':       ('cmdScript.sha256',          '='),
                'is_complete':  ('cmdScript.isComplete',      '='),
            }
        },
        # ── Cross Process ──────────────────────────────────────────────────────
        'CROSS_PROCESS': {
            'filter': 'event.category = "Cross Process"',
            'fields': {
                'tgt_process':  ('tgt.process.name',      'contains:anycase'),
                'tgt_image':    ('tgt.process.image.path','endswith:anycase'),
                'access_rights':('tgt.process.accessRights', '='),
                'dup_handle':   ('event.crossProcess.dupRemoteProcessHandleCount', '>'),
                'open_process': ('event.crossProcess.openProcessCount', '>'),
                'remote_thread':('event.crossProcess.threadCreateCount', '>'),
            }
        },
        # ── DNS ────────────────────────────────────────────────────────────────
        'DNS': {
            'filter': 'event.type = "DNS Query"',
            'fields': {
                'domain':       ('event.dns.request',  '='),
                'request':      ('event.dns.request',  'contains:anycase'),
                'response':     ('event.dns.response', 'contains:anycase'),
                'response_ip':  ('event.dns.response', 'contains:anycase'),
            }
        },
        # ── Driver ─────────────────────────────────────────────────────────────
        'DRIVER': {
            'filter': 'event.type = "Driver Load"',
            'fields': {
                'path':         ('driver.path',         'contains:anycase'),
                'sha256':       ('driver.sha256',        '='),
                'signed_status':('driver.signedStatus',  '='),
                'certificate':  ('driver.certificate',   'contains:anycase'),
            }
        },
        # ── Files ──────────────────────────────────────────────────────────────
        'FILE': {
            'filter': 'event.category = "File"',
            'fields': {
                'path':         ('tgt.file.path',      'contains:anycase'),
                'name':         ('tgt.file.path',      'endswith:anycase'),
                'extension':    ('tgt.file.extension', '='),
                'sha256':       ('tgt.file.sha256',    '='),
                'old_path':     ('tgt.file.oldPath',   'contains:anycase'),
            }
        },
        'FILE_CREATION': {
            'filter': 'event.type = "File Creation"',
            'fields': {
                'path':         ('tgt.file.path',      'contains:anycase'),
                'extension':    ('tgt.file.extension', '='),
                'sha256':       ('tgt.file.sha256',    '='),
            }
        },
        'FILE_MODIFICATION': {
            'filter': 'event.type = "File Modification"',
            'fields': {
                'path':         ('tgt.file.path',      'contains:anycase'),
                'extension':    ('tgt.file.extension', '='),
                'sha256':       ('tgt.file.sha256',    '='),
            }
        },
        'FILE_DELETION': {
            'filter': 'event.type = "File Deletion"',
            'fields': {
                'path':         ('tgt.file.path',      'contains:anycase'),
                'extension':    ('tgt.file.extension', '='),
            }
        },
        'FILE_RENAME': {
            'filter': 'event.type = "File Rename"',
            'fields': {
                'path':         ('tgt.file.path',      'contains:anycase'),
                'old_path':     ('tgt.file.oldPath',   'contains:anycase'),
                'extension':    ('tgt.file.extension', '='),
            }
        },
        # ── Indicators ─────────────────────────────────────────────────────────
        'INDICATOR': {
            'filter': 'event.category = "Indicator"',
            'fields': {}
        },
        # ── Logins / Logouts ───────────────────────────────────────────────────
        'LOGIN': {
            'filter': 'event.type = "Login"',
            'fields': {
                'user':         ('event.login.loginAccountName', 'contains:anycase'),
                'login_type':   ('event.login.type',             '='),
                'is_admin':     ('event.login.isAdministratorEquivalent', '='),
                'is_success':   ('event.login.isSuccessful',     '='),
                'remote_ip':    ('event.login.networkSource.ip.address', '='),
            }
        },
        'LOGOUT': {
            'filter': 'event.type = "Logout"',
            'fields': {
                'user':         ('event.login.loginAccountName', 'contains:anycase'),
            }
        },
        'LOGIN_FAILED': {
            'filter': 'event.type = "Login" AND event.login.isSuccessful = false',
            'fields': {
                'user':         ('event.login.loginAccountName', 'contains:anycase'),
                'remote_ip':    ('event.login.networkSource.ip.address', '='),
            }
        },
        # ── Modules (DLL) ──────────────────────────────────────────────────────
        'MODULE_LOAD': {
            'filter': 'event.type = "Module Load"',
            'fields': {
                'path':         ('module.path',         'contains:anycase'),
                'name':         ('module.path',         'endswith:anycase'),
                'sha256':       ('module.sha256',        '='),
                'signed_status':('module.signedStatus',  '='),
            }
        },
        # ── Network Actions ────────────────────────────────────────────────────
        'NETWORK': {
            'filter': 'event.category = "Ip"',
            'fields': {
                'dst_ip':       ('dst.ip.address',          '='),
                'src_ip':       ('src.ip.address',          '='),
                'dst_port':     ('dst.port.number',         '='),
                'src_port':     ('src.port.number',         '='),
                'protocol':     ('networkConnection.protocol', '='),
                'direction':    ('networkConnection.direction', '='),
                'country':      ('dst.ip.location.countryName', '='),
            }
        },
        'NETWORK_CONNECT': {
            'filter': 'event.type = "IP Connect"',
            'fields': {
                'dst_ip':       ('dst.ip.address',  '='),
                'src_ip':       ('src.ip.address',  '='),
                'dst_port':     ('dst.port.number', '='),
                'protocol':     ('networkConnection.protocol', '='),
                'country':      ('dst.ip.location.countryName', '='),
            }
        },
        'NETWORK_DISCONNECT': {
            'filter': 'event.type = "IP Disconnect"',
            'fields': {
                'dst_ip':       ('dst.ip.address',  '='),
                'src_ip':       ('src.ip.address',  '='),
                'dst_port':     ('dst.port.number', '='),
            }
        },
        # ── Registry ───────────────────────────────────────────────────────────
        'REGISTRY': {
            'filter': 'event.category = "Registry"',
            'fields': {
                'key_path':     ('registry.keyPath', 'contains:anycase'),
                'value':        ('registry.value',   'contains:anycase'),
                'data':         ('registry.data',    'contains:anycase'),
            }
        },
        'REGISTRY_MODIFIED': {
            'filter': 'event.type = "Registry Value Modified"',
            'fields': {
                'key_path':     ('registry.keyPath', 'contains:anycase'),
                'value':        ('registry.value',   'contains:anycase'),
            }
        },
        'REGISTRY_CREATED': {
            'filter': 'event.type IN ("Registry Value Created", "Registry Key Created")',
            'fields': {
                'key_path':     ('registry.keyPath', 'contains:anycase'),
                'value':        ('registry.value',   'contains:anycase'),
            }
        },
        'REGISTRY_DELETED': {
            'filter': 'event.type IN ("Registry Value Deleted", "Registry Key Deleted")',
            'fields': {
                'key_path':     ('registry.keyPath', 'contains:anycase'),
            }
        },
        # ── Scheduled Tasks ────────────────────────────────────────────────────
        'SCHEDULED_TASK': {
            'filter': 'event.category = "Scheduled Task"',
            'fields': {
                'name':         ('scheduledTask.name',       'contains:anycase'),
                'action':       ('scheduledTask.action',     'contains:anycase'),
                'status':       ('scheduledTask.status',     '='),
            }
        },
        # ── URL ────────────────────────────────────────────────────────────────
        'URL': {
            'filter': 'event.category = "Url"',
            'fields': {
                'url':          ('networkConnection.url.address', 'contains:anycase'),
                'domain':       ('networkConnection.url.address', 'contains:anycase'),
                'dst_ip':       ('dst.ip.address',               '='),
                'dst_port':     ('dst.port.number',              '='),
            }
        },
        # ── Named Pipe ─────────────────────────────────────────────────────────
        'NAMED_PIPE': {
            'filter': 'event.type = "Named Pipe Creation"',
            'fields': {
                'name':         ('event.namedPipe.name', 'contains:anycase'),
            }
        },
    }

    # Common cross-event filters (always available)
    _COMMON_FIELDS = {
        'endpoint':     ('endpoint.name',     'contains:anycase'),
        'os':           ('endpoint.os',       '='),
        'site':         ('site.name',         'contains:anycase'),
        'src_process':  ('src.process.name',  'contains:anycase'),
        'src_user':     ('src.process.user',  'contains:anycase'),
        'src_cmdline':  ('src.process.cmdline', 'contains:anycase'),
        'src_image':    ('src.process.image.path', 'endswith:anycase'),
        'storyline_id': ('src.process.storyline.id', '='),
        'agent_uuid':   ('agent.uuid',        '='),
        'site_id':      ('site.id',           '='),
    }

    def __init__(self, xdr_token: str = None, region: str = 'eu1'):
        self.region = region
        self._token = xdr_token
        self._logger = logging.getLogger(__name__)

    def _call_xdr(self, payload: dict, timeout: int = 60) -> dict:
        """
        Single HTTP entry-point for all XDR /api/query calls.
        Accepts a dict payload, POSTs to the XDR endpoint, returns parsed JSON.
        """
        import urllib.request as _req
        url  = self.BASE_URL.format(region=self.region)
        body = json.dumps(payload).encode()
        req  = _req.Request(url, data=body, headers={
            'Authorization': f'Bearer {self.token}',
            'Content-Type':  'application/json',
        })
        with _req.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())

    @property
    def token(self) -> str:
        if self._token:
            return self._token
        try:
            from helpers.keyvault_helper import KeyVaultHelper
            self._token = KeyVaultHelper().get_secret('S1-XDR-TOKEN')
            if self._token:
                return self._token
        except Exception as e:
            self._logger.debug(f"KeyVault lookup failed: {e}")
        env_token = os.environ.get('S1_XDR_TOKEN')
        if env_token:
            self._token = env_token
            return self._token
        raise RuntimeError(
            "XDR token not available. "
            "Set Key Vault secret 'S1-XDR-TOKEN' or env var S1_XDR_TOKEN."
        )

    @dag_node('sentinelone_dataset__query')
    def query(
        self,
        scan_id: str = '',
        event_type: str = '',
        hours: int = 24,
        start=None,
        end=None,
        query_type: str = 'log',
        extra: str = None,
        **filters,
    ) -> list:
        """
        Query the XDR Data Lake by event type with optional field filters.

        Args:
            event_type:   One of the keys in _EVENT_MAP (e.g. 'PROCESS_CREATION',
                          'DNS', 'LOGIN', 'FILE_CREATION', 'NETWORK', etc.)
                          Also accepts raw S1QL v2 strings if event_type is not
                          a known key — passed through as-is.
            hours:        Look-back window (default 24h)
            start / end:  Override time range (datetime or "YYYY-MM-DD HH:MM:SS")
            query_type:   'log' (default) or 'events'
            extra:        Raw S1QL v2 fragment appended with AND
            **filters:    Event-specific + common keyword filters. Examples:
                            image='mimikatz.exe', cmdline='sekurlsa',
                            dst_ip='1.2.3.4', domain='.onion',
                            endpoint='DC01', os='windows',
                            src_user='Administrator', sha256='abc...'

        Returns:
            List of event attribute dicts sorted by event.time ascending.

        Examples:
            xdr.query('PROCESS_CREATION', image='mimikatz.exe', hours=2)
            xdr.query('DNS', domain='.onion', endpoint='WORKSTATION01')
            xdr.query('LOGIN', is_admin=True, login_type='Network', hours=8)
            xdr.query('FILE_CREATION', extension='locked', hours=1)
            xdr.query('REGISTRY_MODIFIED', key_path='CurrentVersion\\Run')
            xdr.query('NETWORK_CONNECT', dst_port=4444, country='Russia')
            xdr.query('COMMAND_SCRIPT', content='Invoke-Mimikatz')
            xdr.query('CROSS_PROCESS', tgt_process='lsass.exe')
            xdr.query('MODULE_LOAD', name='samlib.dll')
            xdr.query('NAMED_PIPE', name='\\\\psexec')
            xdr.query('DRIVER', signed_status='unsigned')
            xdr.query('SCHEDULED_TASK', action='powershell')
            xdr.query('URL', url='pastebin.com')
        """
        from datetime import datetime as dt, timezone, timedelta

        # ── Resolve event definition ──────────────────────────────────────────
        event_key = event_type.upper().replace(' ', '_').replace('-', '_')
        event_def = self._EVENT_MAP.get(event_key)

        if event_def:
            base_filter = event_def['filter']
            field_map = {**self._COMMON_FIELDS, **event_def['fields']}
        else:
            # Raw S1QL v2 passthrough
            base_filter = event_type
            field_map = self._COMMON_FIELDS

        # ── Build filter parts ────────────────────────────────────────────────
        parts = [base_filter]

        for kwarg, value in filters.items():
            if value is None:
                continue
            if kwarg in field_map:
                field, operator = field_map[kwarg]
                if isinstance(value, bool):
                    parts.append(f'{field} = {str(value).lower()}')
                elif isinstance(value, (int, float)) and operator in ('=', '>', '<', '>=', '<=', '!='):
                    parts.append(f'{field} {operator} {value}')
                else:
                    parts.append(f'{field} {operator} "{value}"')
            else:
                # Unknown kwarg: treat as raw field = value
                self._logger.warning(
                    f"Unknown filter '{kwarg}' for event_type '{event_type}'. "
                    f"Appending as raw: {kwarg} = \"{value}\""
                )
                parts.append(f'{kwarg} = "{value}"')

        if extra:
            parts.append(extra)

        filter_str = ' AND '.join(parts)

        # ── Resolve time range ────────────────────────────────────────────────
        def _fmt(t):
            if isinstance(t, dt):
                return t.strftime('%Y-%m-%d %H:%M:%S')
            return str(t) if t else None

        now = dt.now(timezone.utc)
        start_str = _fmt(start) if start else (now - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
        end_str   = _fmt(end)   if end   else now.strftime('%Y-%m-%d %H:%M:%S')

        # ── Execute ───────────────────────────────────────────────────────────
        data = self._call_xdr({
            'queryType': query_type,
            'filter':    filter_str,
            'startTime': start_str,
            'endTime':   end_str,
        })

        matches = data.get('matches', [])
        self._last_response_meta = {
            'continuationToken': data.get('continuationToken'),
            'status':            data.get('status'),
            'raw_keys':          list(data.keys()),
        }
        return sorted(
            [m.get('attributes', {}) for m in matches],
            key=lambda x: x.get('event.time', 0)
        )

    PQ_URL = 'https://xdr.{region}.sentinelone.net/api/powerQuery'

    @dag_node('sentinelone_dataset__power_query')
    def power_query(self, scan_id: str = '', query: str = '', hours: int = 24, start=None, end=None, timeout: int = 60) -> list:
        """
        Execute a PowerQuery (pipes, group, filter, columns) against the XDR Data Lake.

        Uses /api/powerQuery — supports full S1QL aggregation syntax:
            event.type == "IP Connect" | group count() by src.ip.address | filter count >= 5

        startTime accepts relative strings ("24h", "7d") or "YYYY-MM-DD HH:MM:SS".

        Returns: list of row dicts from matches[].attributes
        """
        from datetime import datetime as dt, timezone, timedelta

        def _fmt(t):
            if isinstance(t, dt):
                return t.strftime('%Y-%m-%d %H:%M:%S')
            return str(t) if t else None

        now = dt.now(timezone.utc)
        start_str = _fmt(start) if start else f'{hours}h'
        end_str   = _fmt(end)   if end   else now.strftime('%Y-%m-%d %H:%M:%S')

        payload = {
            'query':     query,
            'startTime': start_str,
            'endTime':   end_str,
        }

        import urllib.request as _req
        url  = self.PQ_URL.format(region=self.region)
        body = json.dumps(payload).encode()
        req  = _req.Request(url, data=body, headers={
            'Authorization': f'Bearer {self.token}',
            'Content-Type':  'application/json',
        })
        try:
            with _req.urlopen(req, timeout=timeout) as r:
                resp = json.loads(r.read())
        except _req.HTTPError as e:
            body_err = e.read()
            raise RuntimeError(f'powerQuery HTTP {e.code}: {body_err.decode()[:1000]}')

        matches = resp.get('matches', resp.get('rows', resp.get('data', [])))
        if matches:
            return [m.get('attributes', m) for m in matches]

        # Alternative response format: {columns: [{name}...], values: [[v1,v2...]...]}
        columns = resp.get('columns', [])
        values  = resp.get('values', [])
        if columns and values:
            col_names = [c['name'] for c in columns]
            return [dict(zip(col_names, row)) for row in values]

        return []

    @dag_node('sentinelone_dataset__raw_query_with_meta')
    def raw_query_with_meta(self, scan_id: str = '', filter_str: str = '', hours: int = 24, start=None, end=None) -> dict:
        """
        Like raw_query but returns the full API response so callers can inspect
        what fields the XDR API returns beyond just matches (e.g. total, pagination).
        """
        from datetime import datetime as dt, timezone, timedelta

        def _fmt(t):
            if isinstance(t, dt):
                return t.strftime('%Y-%m-%d %H:%M:%S')
            return str(t) if t else None

        now = dt.now(timezone.utc)
        start_str = _fmt(start) if start else (now - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
        end_str   = _fmt(end)   if end   else now.strftime('%Y-%m-%d %H:%M:%S')

        raw = self._call_xdr({
            'queryType': 'log',
            'filter':    filter_str,
            'startTime': start_str,
            'endTime':   end_str,
        })

        matches = raw.get('matches', [])
        events = sorted(
            [m.get('attributes', {}) for m in matches],
            key=lambda x: x.get('event.time', 0)
        )
        meta = {k: v for k, v in raw.items() if k != 'matches'}
        return {'events': events, 'meta': meta, 'raw': raw}

    # XDR event.type string -> UI tab key
    _XDR_TYPE_TO_UI = {
        'process creation':        'process_creation',
        'ip connect':              'ip_connect',
        'dns resolved':            'dns_resolved',
        'url':                     'url',
        'file creation':           'file_creation',
        'registry key create':     'registry_key_create',
        'scheduled task creation': 'scheduled_task_creation',
        'command script':          'command_script',
        'cross process open':      'cross_process_open',
        'login':                   'login',
        'behavioral indicator':    'behavioral_indicators',
        'driver load':             'driver_load',
    }

    @dag_node('sentinelone_dataset__count_events_by_type')
    def count_events_by_type(self, scan_id: str = '', filter_str: str = '', start=None, end=None) -> dict:
        """
        Get real event counts per type using a single aggregation query:

            <filter> | group count() by event.type

        One request, real numbers, fully scalable.
        Returns dict: {'all': N, 'process_creation': N, 'ip_connect': N, ...}
        """
        from datetime import datetime as dt, timezone, timedelta

        def _fmt(t):
            if isinstance(t, dt):
                return t.strftime('%Y-%m-%d %H:%M:%S')
            return str(t) if t else None

        now       = dt.now(timezone.utc)
        start_str = _fmt(start) if start else (now - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        end_str   = _fmt(end)   if end   else now.strftime('%Y-%m-%d %H:%M:%S')

        # Build aggregation query: filter (optional) piped into group count by event.type
        if filter_str and filter_str.strip():
            agg_query = f'{filter_str.strip()} | group count() by event.type'
        else:
            agg_query = '| group count() by event.type'

        try:
            resp = self._call_xdr({
                'queryType': 'pq',
                'query':     agg_query,
                'startTime': start_str,
                'endTime':   end_str,
            })
        except Exception as e:
            self._logger.warning(f'count_events_by_type aggregation query failed: {e}')
            return {'all': 0}

        # The PQ response returns rows with {event.type, count} columns.
        # Column names may vary — try common shapes.
        rows    = resp.get('matches', resp.get('rows', resp.get('data', [])))
        counts  = {}
        all_cnt = 0

        for row in rows:
            attrs  = row.get('attributes', row)  # some responses wrap in attributes
            etype  = (
                attrs.get('event.type') or
                attrs.get('eventType')  or
                attrs.get('type', '')
            ).lower().strip()
            cnt = int(
                attrs.get('count') or
                attrs.get('count()') or
                attrs.get('_count', 0)
            )
            ui_key = self._XDR_TYPE_TO_UI.get(etype, etype.replace(' ', '_'))
            counts[ui_key] = counts.get(ui_key, 0) + cnt
            all_cnt += cnt

        counts['all'] = all_cnt
        return counts

    # Default values reused by nodes.py field schema
    _IP_CONNECT_DEFAULT_STATUSES   = ["FAILURE", "RESET", "REFUSED"]
    _IP_CONNECT_DEFAULT_PORTS      = [135, 139, 445, 3389, 5985, 5986, 22, 23]
    _IP_CONNECT_DEFAULT_EXCL_PROCS = [
        "ntoskrnl.exe", "lsass.exe", "svchost.exe",
        "backgroundtaskhost.exe", "system",
    ]
    _IP_CONNECT_PRIVATE_PREFIXES   = [
        "10.", "192.168.",
        "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
        "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
    ]

    @dag_node('sentinelone_dataset__powerquery_ip_connect')
    def powerquery_ip_connect(
        self,
        scan_id: str = '',
        hours: int = 72,
        unique_hosts: int = 10,
        total_connections: int = 20,
        connection_statuses: list[str] = None,
        dst_ports: list[int] = None,
        src_process_exclusions: list[str] = None,
        extra_filter: str = '',
    ) -> list[dict]:
        """
        Detect lateral-movement / port-scan activity using the refined XDR PowerQuery.

        Builds the canonical S1QL query:
            event.type == "IP Connect"
            && direction OUTGOING
            && connectionStatus in connection_statuses
            && dst.ip.address in private ranges
            && dst.port.number in dst_ports
            && !(src.process.name in src_process_exclusions)
            | group UniqueHosts, TotalConnections by src.ip.address
            | filter UniqueHosts >= unique_hosts && TotalConnections >= total_connections

        Returns list of dicts: [{SourceIP, UniqueHosts, TotalConnections}]

        Args:
            hours                  — look-back window (default 72)
            unique_hosts           — min distinct destination IPs (default 10)
            total_connections      — min total connection events (default 20)
            connection_statuses    — list of statuses to include (default: FAILURE/RESET/REFUSED)
            dst_ports              — list of destination ports to match (default: SMB/RDP/WinRM/SSH)
            src_process_exclusions — process names to exclude (default: ntoskrnl/lsass/svchost/...)
            extra_filter           — raw S1QL fragment appended with &&
        """
        statuses   = connection_statuses  or self._IP_CONNECT_DEFAULT_STATUSES
        ports      = dst_ports            or self._IP_CONNECT_DEFAULT_PORTS
        excl_procs = src_process_exclusions or self._IP_CONNECT_DEFAULT_EXCL_PROCS

        # Build each clause
        status_clause = " || ".join(
            f'event.network.connectionStatus == "{s}"' for s in statuses
        )
        prefix_clause = " || ".join(
            f'dst.ip.address contains "{p}"' for p in self._IP_CONNECT_PRIVATE_PREFIXES
        )
        port_clause = " || ".join(
            f'dst.port.number == {p}' for p in ports
        )
        excl_clause = " && ".join(
            f'!(src.process.name contains:anycase "{p}")' for p in excl_procs
        )

        parts = [
            'event.type == "IP Connect"',
            'event.network.direction == "OUTGOING"',
            f'({status_clause})',
            f'({prefix_clause})',
            '!(dst.ip.address == "127.0.0.1")',
            '!(src.ip.address == "127.0.0.1")',
            f'({port_clause})',
            excl_clause,
        ]
        if extra_filter:
            parts.append(extra_filter)

        filter_str = " && ".join(parts)

        query = (
            f"{filter_str} "
            f"\n| group UniqueHosts = estimate_distinct(dst.ip.address), TotalConnections = count() by src.ip.address "
            f"\n| filter UniqueHosts >= {unique_hosts} && TotalConnections >= {total_connections} "
            f"\n| columns SourceIP=src.ip.address, UniqueHosts\n"
        )

        return self.power_query(scan_id=scan_id, query=query, hours=hours)

    @dag_node('sentinelone_dataset__raw_query')
    def raw_query(self, scan_id: str = '', filter_str: str = '', hours: int = 24, start=None, end=None) -> list:
        """
        Execute a raw S1QL v2 filter string directly against the Data Lake.
        Use when you need full control over the query.
        """
        return self.query(scan_id=scan_id, event_type=filter_str, hours=hours, start=start, end=end)

    @classmethod
    def event_types(cls) -> list:
        """Return the list of supported event_type keys."""
        return sorted(cls._EVENT_MAP.keys())

    # ── Alert Management (GraphQL via authenticated browser CDP) ─────────────

    GRAPHQL_URL = 'https://xdr.{region}.sentinelone.net/v2/graphql'

    # Path to the Node.js helper for XDR GraphQL via CDP
    _CDP_HELPER_DIR = os.path.join(
        os.path.expanduser('~'),
        '.openclaw', 'workspace', 'skills', 'verify-on-browser'
    )

    @dag_node('sentinelone_dataset__create_alert')
    def create_alert(
        self,
        scan_id: str = '',
        description: str = '',
        s1ql_query: str = '',
        note: str = '',
        evaluation_frequency: int = 1,
        grace_period: int = 0,
        renotify_period: int = 60,
        resolution_delay: int = 0,
        alert_addresses: str = '',
        site_ids: list = None,
        threshold: int = 0,
        window_minutes: int = 1,
    ) -> dict:
        """
        Create an XDR alert (SINGLE type) via the GraphQL API using the
        authenticated chrome-agent browser session (CDP via Node.js).

        Auth strategy:
          1. Connects to chrome-agent CDP (localhost:9222) via Node/Playwright
          2. Reloads the active XDR page to intercept a real GraphQL request
          3. Captures x-csrf-token + scalyr-team-token from intercepted headers
          4. Sends CreateAlert mutation with those headers via context.request
             (which shares the browser's cookie jar with EDGE_USER_TOKEN)

        The alert trigger format is:
            count:<window_minutes> minutes(<s1ql_query>) > <threshold>

        Args:
            description:          Alert name/title shown in XDR UI.
            s1ql_query:           S1QL v2 filter string (without SELECT/FROM).
            note:                 Optional markdown note/description.
            evaluation_frequency: Minutes between evaluations (default 1).
            grace_period:         Minutes before alert fires after condition met (default 0).
            renotify_period:      Minutes between re-notifications (default 60).
            resolution_delay:     Minutes to wait before auto-resolving (default 0).
            alert_addresses:      Notification target e.g. 'pagerduty:TOKEN' or 'email:foo@bar.com'.
            site_ids:             List of SentinelOne site IDs to scope. Empty = all sites.
            threshold:            Alert fires when count > threshold (default 0 = any event).
            window_minutes:       Time window for count aggregation in minutes (min 1 = 60s).

        Returns:
            dict with alert creation result from GraphQL (alertId, description, trigger, ...).

        Raises:
            RuntimeError on GraphQL errors or if browser is not authenticated.

        Example:
            xdr = SentinelDataLakeHelper()
            result = xdr.create_alert(
                description="LeakNet Deno-Based In-Memory Loader",
                s1ql_query=(
                    "event.category = 'PROCESS'\\n"
                    "AND tgt.process.image.path EndsWith '\\\\\\\\deno.exe'\\n"
                    "AND tgt.process.cmdline contains '-A'\\n"
                    "AND tgt.process.cmdline contains 'data:application/javascript'\\n"
                    "AND tgt.process.cmdline contains 'base64,'"
                ),
                note="T1059.007, T1620 — BYOR technique by LeakNet group.",
                alert_addresses="pagerduty:YOUR_TOKEN",
            )
            print(result['alertId'])
        """
        import subprocess as _sp
        import tempfile as _tmp

        trigger = f"count:{window_minutes} minutes({s1ql_query}) > {threshold}"

        mutation = (
            "mutation CreateAlert($alert: AlertInput!) {"
            " createAlert(alert: $alert) {"
            " alertId alertAddresses description gracePeriod note"
            " renotifyPeriod resolutionDelay evaluationFrequency trigger __typename"
            " } }"
        )

        payload = {
            'operationName': 'CreateAlert',
            'variables': {
                'alert': {
                    'description': description,
                    'evaluationFrequency': evaluation_frequency,
                    'gracePeriod': grace_period,
                    'note': note,
                    'renotifyPeriod': renotify_period,
                    'resolutionDelay': resolution_delay,
                    'type': 'SINGLE',
                    'siteIds': site_ids or [],
                    'alertAddresses': alert_addresses,
                    'trigger': trigger,
                }
            },
            'query': mutation,
        }

        graphql_url = self.GRAPHQL_URL.format(region=self.region)

        # Write a temporary Node.js script that:
        # 1. Connects to CDP, reloads XDR page to intercept real auth headers
        # 2. Sends CreateAlert with those headers
        # 3. Prints JSON result to stdout
        node_script = r"""
const { chromium } = require('playwright');
const payload = JSON.parse(process.argv[2]);
const graphqlUrl = process.argv[3];

(async () => {
  const browser = await chromium.connectOverCDP('http://localhost:9222');
  const context = browser.contexts()[0];
  if (!context) throw new Error('No browser context on CDP port 9222');

  const pages = context.pages();
  const xdrPage = pages.find(p => p.url().includes('xdr.') && p.url().includes('sentinelone.net'));
  if (!xdrPage) throw new Error('No active XDR page — open xdr.eu1.sentinelone.net in chrome-agent');

  let authHeaders = null;
  await xdrPage.route('**/v2/graphql**', async (route, request) => {
    const h = request.headers();
    if (!authHeaders && h['x-csrf-token']) authHeaders = h;
    await route.continue();
  });

  await xdrPage.reload({ timeout: 20000, waitUntil: 'domcontentloaded' }).catch(() => {});
  await new Promise(r => setTimeout(r, 3000));

  if (!authHeaders) throw new Error('Could not capture auth headers from XDR page');

  const response = await context.request.post(graphqlUrl, {
    headers: { ...authHeaders, 'content-type': 'application/json' },
    data: JSON.stringify(payload),
  });

  const body = await response.json();
  process.stdout.write(JSON.stringify(body));
  await browser.close();
})().catch(e => { process.stderr.write(e.message); process.exit(1); });
"""

        with _tmp.NamedTemporaryFile(suffix='.cjs', mode='w', delete=False) as f:
            f.write(node_script)
            script_path = f.name

        try:
            result = _sp.run(
                ['node', script_path, json.dumps(payload), graphql_url],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=self._CDP_HELPER_DIR,
            )
        finally:
            os.unlink(script_path)

        if result.returncode != 0:
            raise RuntimeError(
                f"CDP Node script failed: {result.stderr.strip()}"
            )

        data = json.loads(result.stdout)
        errors = data.get('errors')
        if errors:
            raise RuntimeError(f"GraphQL error creating XDR alert: {errors}")

        return data.get('data', {}).get('createAlert', {})

    @dag_node('sentinelone_dataset__count_by', brand='SentinelOne', label='Count By Event Type')
    def count_by(self, scan_id: str = '', filter_str: str = '', start=None, end=None) -> dict:
        """Alias for count_events_by_type — counts events grouped by type."""
        return self.count_events_by_type(scan_id=scan_id, filter_str=filter_str, start=start, end=end)

    @dag_node('sentinelone_dataset__ip_connect_scan', brand='SentinelOne', label='IP Connect Scan')
    def ip_connect_scan(self, scan_id: str = '', hours: int = 72, unique_hosts: int = 10,
                        total_connections: int = 20, connection_statuses: list = None,
                        dst_ports: list = None, src_process_exclusions: list = None,
                        extra_filter: str = '') -> list:
        """Alias for powerquery_ip_connect — scans for suspicious outbound IP connections."""
        return self.powerquery_ip_connect(
            scan_id=scan_id, hours=hours, unique_hosts=unique_hosts,
            total_connections=total_connections, connection_statuses=connection_statuses,
            dst_ports=dst_ports, src_process_exclusions=src_process_exclusions,
            extra_filter=extra_filter,
        )
