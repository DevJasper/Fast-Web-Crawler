#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <libxml/HTMLparser.h>
#include <libxml/xpath.h>
#include <libxml/uri.h>
#include <math.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define DIR "store"
#define MAXC 100

/* Parameters */
int max_con = 200;
int max_total = 20000;
int max_requests = 500;
int max_link_per_page = 100;
int follow_relative_links = 0;

int pending_interrupt = 0;
void sighandler(int dummy)
{
  pending_interrupt = 1;
}

/* resizable buffer */
typedef struct
{
  char *buf;
  size_t size;
} memory;

typedef struct url_parser_url
{
  char *protocol;
  char *host;
  int port;
  char *path;
  char *query_string;
  int host_exists;
  char *host_ip;
} url_parser_url_t;

void free_parsed_url(url_parser_url_t *url_parsed)
{
  if (url_parsed->protocol)
    free(url_parsed->protocol);
  if (url_parsed->host)
    free(url_parsed->host);
  if (url_parsed->path)
    free(url_parsed->path);
  if (url_parsed->query_string)
    free(url_parsed->query_string);

  free(url_parsed);
}

int parse_url(char *url, bool verify_host, url_parser_url_t *parsed_url)
{
  char *local_url = (char *)malloc(sizeof(char) * (strlen(url) + 1));
  char *token;
  char *token_host;
  char *host_port;
  char *host_ip;

  char *token_ptr;
  char *host_token_ptr;

  char *path = NULL;

  // Copy our string
  strcpy(local_url, url);

  token = strtok_r(local_url, ":", &token_ptr);
  parsed_url->protocol = (char *)malloc(sizeof(char) * strlen(token) + 1);
  strcpy(parsed_url->protocol, token);

  // Host:Port
  token = strtok_r(NULL, "/", &token_ptr);
  if (token)
  {
    host_port = (char *)malloc(sizeof(char) * (strlen(token) + 1));
    strcpy(host_port, token);
  }
  else
  {
    host_port = (char *)malloc(sizeof(char) * 1);
    strcpy(host_port, "");
  }

  token_host = strtok_r(host_port, ":", &host_token_ptr);
  parsed_url->host_ip = NULL;
  if (token_host)
  {
    parsed_url->host = (char *)malloc(sizeof(char) * strlen(token_host) + 1);
    strcpy(parsed_url->host, token_host);

    if (verify_host)
    {
      struct hostent *host;
      host = gethostbyname(parsed_url->host);
      if (host != NULL)
      {
        parsed_url->host_ip = inet_ntoa(*(struct in_addr *)host->h_addr);
        parsed_url->host_exists = 1;
      }
      else
      {
        parsed_url->host_exists = 0;
      }
    }
    else
    {
      parsed_url->host_exists = -1;
    }
  }
  else
  {
    parsed_url->host_exists = -1;
    parsed_url->host = NULL;
  }

  // Port
  token_host = strtok_r(NULL, ":", &host_token_ptr);
  if (token_host)
    parsed_url->port = atoi(token_host);
  else
    parsed_url->port = 0;

  token_host = strtok_r(NULL, ":", &host_token_ptr);
  assert(token_host == NULL);

  token = strtok_r(NULL, "?", &token_ptr);
  parsed_url->path = NULL;
  if (token)
  {
    path = (char *)realloc(path, sizeof(char) * (strlen(token) + 2));
    strcpy(path, "/");
    strcat(path, token);

    parsed_url->path = (char *)malloc(sizeof(char) * strlen(path) + 1);
    strncpy(parsed_url->path, path, strlen(path));

    free(path);
  }
  else
  {
    parsed_url->path = (char *)malloc(sizeof(char) * 2);
    strcpy(parsed_url->path, "/");
  }

  token = strtok_r(NULL, "?", &token_ptr);
  if (token)
  {
    parsed_url->query_string = (char *)malloc(sizeof(char) * (strlen(token) + 1));
    strncpy(parsed_url->query_string, token, strlen(token));
  }
  else
  {
    parsed_url->query_string = NULL;
  }

  token = strtok_r(NULL, "?", &token_ptr);
  // assert(token == NULL);

  free(local_url);
  free(host_port);
  return 0;
}

size_t grow_buffer(void *contents, size_t sz, size_t nmemb, void *ctx)
{
  size_t realsize = sz * nmemb;
  memory *mem = (memory *)ctx;
  char *ptr = (char *)realloc(mem->buf, mem->size + realsize);
  if (!ptr)
  {
    /* out of memory */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }
  mem->buf = ptr;
  memcpy(&(mem->buf[mem->size]), contents, realsize);
  mem->size += realsize;
  return realsize;
}

CURL *make_handle(char *url)
{
  CURL *handle = curl_easy_init();

  /* Important: use HTTP2 over HTTPS */
  curl_easy_setopt(handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
  curl_easy_setopt(handle, CURLOPT_URL, url);

  /* buffer body */
  memory *mem = (memory *)malloc(sizeof(memory));
  mem->size = 0;
  mem->buf = (char *)malloc(1);
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, grow_buffer);
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, mem);
  curl_easy_setopt(handle, CURLOPT_PRIVATE, mem);

  /* For completeness */
  curl_easy_setopt(handle, CURLOPT_ACCEPT_ENCODING, "");
  curl_easy_setopt(handle, CURLOPT_TIMEOUT, 5L);
  curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(handle, CURLOPT_MAXREDIRS, 10L);
  curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, 2L);
  curl_easy_setopt(handle, CURLOPT_COOKIEFILE, "");
  curl_easy_setopt(handle, CURLOPT_FILETIME, 1L);
  curl_easy_setopt(handle, CURLOPT_USERAGENT, "Web Crawler");
  curl_easy_setopt(handle, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
  curl_easy_setopt(handle, CURLOPT_UNRESTRICTED_AUTH, 1L);
  curl_easy_setopt(handle, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
  curl_easy_setopt(handle, CURLOPT_EXPECT_100_TIMEOUT_MS, 0L);

  return handle;
}

/* HREF finder implemented in libxml2 but could be any HTML parser */
size_t follow_links(CURLM *multi_handle, memory *mem, char *url)
{
  int opts = HTML_PARSE_NOBLANKS | HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING | HTML_PARSE_NONET;
  htmlDocPtr doc = htmlReadMemory(mem->buf, mem->size, url, NULL, opts);
  if (!doc)
    return 0;
  xmlChar *xpath = (xmlChar *)"//a/@href";
  xmlXPathContextPtr context = xmlXPathNewContext(doc);
  xmlXPathObjectPtr result = xmlXPathEvalExpression(xpath, context);
  xmlXPathFreeContext(context);
  if (!result)
    return 0;
  xmlNodeSetPtr nodeset = result->nodesetval;
  if (xmlXPathNodeSetIsEmpty(nodeset))
  {
    xmlXPathFreeObject(result);
    return 0;
  }
  size_t count = 0;
  for (int i = 0; i < nodeset->nodeNr; i++)
  {
    double r = rand();
    int x = r * nodeset->nodeNr / RAND_MAX;
    const xmlNode *node = nodeset->nodeTab[x]->xmlChildrenNode;
    xmlChar *href = xmlNodeListGetString(doc, node, 1);
    if (follow_relative_links)
    {
      xmlChar *orig = href;
      href = xmlBuildURI(href, (xmlChar *)url);
      xmlFree(orig);
    }
    char *link = (char *)href;
    if (!link || strlen(link) < 20)
      continue;
    if (!strncmp(link, "http://", 7) || !strncmp(link, "https://", 8))
    {
      curl_multi_add_handle(multi_handle, make_handle(link));
      if (count++ == max_link_per_page)
        break;
    }
    xmlFree(link);
  }
  xmlXPathFreeObject(result);
  return count;
}

int is_html(char *ctype)
{
  return ctype != NULL && strlen(ctype) > 10 && strstr(ctype, "text/html");
}

char *trim(char *s)
{
  int i;

  while (isspace(*s))
    s++; // skip left side white spaces
  for (i = strlen(s) - 1; (isspace(s[i])); i--)
    ; // skip right side white spaces
  s[i + 1] = '\0';
  return s;
}

void read_urls_from_file(CURLM *multi_handle, const char *file_name)
{
  char line[MAXC];
  FILE *file = fopen(file_name, "r");
  if (!file)
  {
    fprintf(stderr, "Failed to open URL file '%s'.\n", file_name);
    exit(1);
  }

  while (fgets(line, sizeof line, file))
  {
    curl_multi_add_handle(multi_handle, make_handle(trim(line)));
  }
  fclose(file);
}

int main(void)
{
  signal(SIGINT, sighandler);
  LIBXML_TEST_VERSION;
  curl_global_init(CURL_GLOBAL_DEFAULT);
  CURLM *multi_handle = curl_multi_init();
  curl_multi_setopt(multi_handle, CURLMOPT_MAX_TOTAL_CONNECTIONS, max_con);
  curl_multi_setopt(multi_handle, CURLMOPT_MAX_HOST_CONNECTIONS, 6L);

  /* enables http/2 if available */
#ifdef CURLPIPE_MULTIPLEX
  curl_multi_setopt(multi_handle, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
#endif

  struct stat st = {0};
  if (stat(DIR, &st) == -1)
  {
    mkdir(DIR, 0777);
  }

  //Read URLs from file and push to handler
  read_urls_from_file(multi_handle, "urls.txt");

  int msgs_left;
  int pending = 0;
  int complete = 0;
  int still_running = 1;
  int page_count = 0;
  while (still_running && !pending_interrupt)
  {
    int numfds;
    curl_multi_wait(multi_handle, NULL, 0, 1000, &numfds);
    curl_multi_perform(multi_handle, &still_running);

    /* See how the transfers went */

    CURLMsg *m = NULL;
    while ((m = curl_multi_info_read(multi_handle, &msgs_left)))
    {
      if (m->msg == CURLMSG_DONE)
      {
        CURL *handle = m->easy_handle;
        char *url;
        memory *mem;
        curl_easy_getinfo(handle, CURLINFO_PRIVATE, &mem);
        curl_easy_getinfo(handle, CURLINFO_EFFECTIVE_URL, &url);
        if (m->data.result == CURLE_OK)
        {
          long res_status;
          curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &res_status);
          if (res_status == 200)
          {
            char *ctype;
            curl_easy_getinfo(handle, CURLINFO_CONTENT_TYPE, &ctype);
            printf("[%d] HTTP 200 (%s): %s\n", complete, ctype, url);

            char inner_dir[MAXC];
            url_parser_url_t *parsed_url;
            parsed_url = (url_parser_url_t *)malloc(sizeof(url_parser_url_t));

            int error = parse_url(url, true, parsed_url);
            if (error != 0)
            {
              printf("Failed to parse URL: %s\n", url);
            }
            else
            {
              struct stat st = {0};
              sprintf(inner_dir, "%s/%s", DIR, parsed_url->host);

              if (stat(inner_dir, &st) == -1)
              {
                mkdir(inner_dir, 0777);
              }
              free_parsed_url(parsed_url);
            }

            if (is_html(ctype) && mem->size > 100)
            {
              ++page_count;
              char file_name[MAXC];
              sprintf(file_name, "%s/page-%d.html", inner_dir, page_count);

              FILE *file;
              file = fopen(file_name, "w+");
              fprintf(file, "%s", mem->buf);
              fclose(file);

              if (pending < max_requests && (complete + pending) < max_total)
              {
                pending += follow_links(multi_handle, mem, url);
                still_running = 1;
              }
            }
          }
          else
          {
            printf("[%d] HTTP %d: %s\n", complete, (int)res_status, url);
          }
        }
        else
        {
          printf("[%d] Connection failure: %s\n", complete, url);
        }
        curl_multi_remove_handle(multi_handle, handle);
        curl_easy_cleanup(handle);
        free(mem->buf);
        free(mem);
        complete++;
        pending--;
      }
    }
  }
  curl_multi_cleanup(multi_handle);
  curl_global_cleanup();
  return 0;
}
