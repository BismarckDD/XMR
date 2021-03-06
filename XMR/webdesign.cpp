#include <stdlib.h>

extern const char sHtmlCssEtag [] = "00000006";
extern const char sHtmlCssFile [] =
    "body {"
        "font-family: Tahoma, Arial, sans-serif;"
        "font-size: 80%;"
        "background-color: rgb(240, 240, 240);"
    "}"

    "a {"
        "color: rgb(44, 55, 66);"
    "}"

    "a:link {"
        "text-decoration: none;"
    "}"

    "a:visited {"
        "color: rgb(44, 55, 66);"
    "}"

    "a:hover {"
        "color: rgb(255, 153, 0);"
    "}"

    "a:active {"
        "color: rgb(204, 122, 0);"
    "}"
    
    ".all {"
        "max-width:600px;"
        "margin: auto;"
    "}"
    
    ".header {"
        "background-color: rgb(30, 30, 30);"
        "color: white;"
        "padding: 10px;"
        "font-weight: bold;"
        "margin: 10px 0px;"
    "}"

    ".links {"
        "padding: 7px;"
        "text-align: center;"
        "background-color: rgb(215, 215, 215);"
        "box-shadow: 0px 1px 3px 0px rgba(0, 0, 0, 0.2), 0px 1px 1px 0px rgba(0, 0, 0, 0.14), 0px 2px 1px -1px rgba(0, 0, 0, 0.12);"
    "}"

    ".data th, td {"
        "padding: 5px 12px;"
        "text-align: right;"
        "border-bottom: 1px solid #ccc;"
    "}"

    ".data tr:nth-child(even) {"
        "background-color: #ddd;"
    "}"

    ".data th {"
        "background-color: #ccc;"
    "}"

    ".data table {"
        "width: 100%;"
        "max-width: 600px;"
    "}"

    ".letter {"
        "font-weight: bold;"
    "}"

    "h4 {"
        "background-color: rgb(0, 130, 130);"
        "color: white;"
        "padding: 10px;"
        "margin: 10px 0px;"
    "}"

    ".flex-container {"
        "display: -webkit-flex;"
        "display: flex;"
    "}"

    ".flex-item {"
        "width: 33%;"
        "margin: 3px;"
    "}";

size_t sHtmlCssSize = sizeof(sHtmlCssFile) - 1;

extern const char sHtmlCommonHeader [] =
    "<!DOCTYPE html>"
    "<html>"
    "<head><meta name='viewport' content='width=device-width' />"
    "<link rel='stylesheet' href='style.css' /><title>%s</title></head>"
    "<body>"
    "<div class='all'>"
    "<div class='header'><span style='color: rgb(255, 160, 0)'>XMR</span>-Stak-CPU</div>"

    "<div class='flex-container'>"
        "<div class='links flex-item'>"
            "<a href='/h'><div><span class='letter'>H</span>ashrate</div></a>"
        "</div>"
        "<div class='links flex-item'>"
            "<a href='/r'><div><span class='letter'>R</span>esults</div></a>"
        "</div>"
        "<div class='links flex-item'>"
            "<a href='/c'><div><span class='letter'>C</span>onnection</div></a>"
        "</div>"
    "</div>"
    "<h4>%s</h4>";

extern const char sHtmlHashrateBodyHigh [] =
    "<div class=data>"
    "<table>"
        "<tr><th>Thread ID</th><th>2.5s</th><th>60s</th><th>15m</th><th rowspan='%u'>H/s</td></tr>";

extern const char sHtmlHashrateTableRow [] =
    "<tr><th>%u</th><td>%s</td><td>%s</td><td>%s</td></tr>";

extern const char sHtmlHashrateBodyLow [] =
        "<tr><th>Totals:</th><td>%s</td><td>%s</td><td>%s</td></tr>"
        "<tr><th>Highest:</th><td>%s</td><td colspan='2'></td></tr>"
    "</table>"
    "</div></div></body></html>";

extern const char sHtmlConnectionBodyHigh [] =
    "<div class=data>"
    "<table>"
        "<tr><th>Pool address</th><td>%s</td></tr>"
        "<tr><th>Connected since</th><td>%s</td></tr>"
        "<tr><th>Pool ping time</th><td>%u ms</td></tr>"
    "</table>"
    "<h4>Network error log</h4>"
    "<table>"
        "<tr><th style='width: 20%; min-width: 10em;'>Date</th><th>Error</th></tr>";

extern const char sHtmlConnectionTableRow [] =
    "<tr><td>%s</td><td>%s</td></tr>";

extern const char sHtmlConnectionBodyLow [] =
    "</table></div></div></body></html>";

extern const char sHtmlResultBodyHigh [] =
    "<div class=data>"
    "<table>"
        "<tr><th>Difficulty</th><td>%u</td></tr>"
        "<tr><th>Good results</th><td>%u / %u (%.1f %%)</td></tr>"
        "<tr><th>Avg result time</th><td>%.1f sec</td></tr>"
        "<tr><th>Pool-side hashes</th><td>%u</td></tr>"
    "</table>"
    "<h4>Top 10 best results found</h4>"
    "<table>"
        "<tr><th style='width: 2em;'>1</th><td>%llu</td><th style='width: 2em;'>2</th><td>%llu</td></tr>"
        "<tr><th>3</th><td>%llu</td><th>4</th><td>%llu</td></tr>"
        "<tr><th>5</th><td>%llu</td><th>6</th><td>%llu</td></tr>"
        "<tr><th>7</th><td>%llu</td><th>8</th><td>%llu</td></tr>"
        "<tr><th>9</th><td>%llu</td><th>10</th><td>%llu</td></tr>"
    "</table>"
    "<h4>Error details</h4>"
    "<table>"
        "<tr><th colspan='2'>Error text</th></tr>"
        "<tr><th style='width: 5em;'>Count</th><th>Last seen</th></tr>";

extern const char sHtmlResultTableRow [] =
    "<tr><td colspan='2'>%s</td></tr><tr><td>%llu</td><td>%s</td></tr>";

extern const char sHtmlResultBodyLow [] =
    "</table></div></div></body></html>";

