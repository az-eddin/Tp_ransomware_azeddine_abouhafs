from http.server import BaseHTTPRequestHandler
import logging
from urllib.parse import urlparse, parse_qs
import json
import traceback

class CNCBase(BaseHTTPRequestHandler):

    def execute_method(self, method: str, body: dict) -> None:
        """
        Exécute une méthode (GET ou POST) en fonction du chemin et du corps de la requête.
        """
        self._logger = logging.getLogger(self.__class__.__name__)
        try:
            path, params = self.extract_path_and_params(self.path)
            function_name = self.determine_function_name(path)
            self._logger.info(f"Méthode : {function_name}, Chemin : {path}, Paramètres : {params}")

            func = getattr(self, f"{method}_{function_name}")
            response = func(path, params, body)
            self._logger.debug(f"Réponse : {response}")

            self.end_response(200, response)
        except Exception as e:
            print(traceback.format_exc())
            self.end_response(500, {})

    def end_response(self, code: int, response: dict) -> None:
        """
        Termine la requête en envoyant le code de statut et la réponse JSON.
        """
        if not isinstance(response, dict):
            response = {}

        json_data = json.dumps(response)
        response_body = bytes(json_data, "utf8")
        self.send_response(code)
        self.end_headers()
        self.wfile.write(response_body)

    def do_GET(self) -> None:
        """
        Gèrer les requêtes GET
        """
        return self.execute_method("get", {})

    def do_POST(self) -> None:
        """
        Gère les requêtes POST 
        """
        content_type = self.headers.get('content-type')
        if content_type == 'application/json':
            length = int(self.headers.get('content-length'))
            body = json.loads(self.rfile.read(length))
        else:
            raise Exception("Type de contenu non supporté")

        return self.execute_method("post", body)

    def extract_path_and_params(self, url: str) -> tuple:
        """
        Analyse l'URL pour en extraire le chemin et les paramètres de la requête.
        """
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        return parsed_url.path, params

    def determine_function_name(self, path: str) -> str:
        """
        Extrait le nom de la fonction à partir du chemin de l'URL.
        """
        return path[1:].split("/")[0]
