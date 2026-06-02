# tavily
import requests

def web_search(state: AgentState):
    response = requests.post(
        "https://api.tavily.com/search",
        headers={"Authorization": f"Bearer {TAVILY_API_KEY}"},
        json={
            "query": state["question"],
            "search_depth": "basic",
            "max_results": 5
        }
    )
    data = response.json()
    return {"search_result": data["results"][0]["content"]}  # Tavily-specific field

# switch to brave
def web_search(state: AgentState):
    response = requests.get(
        "https://api.search.brave.com/res/v1/web/search",
        headers={"X-Subscription-Token": BRAVE_API_KEY},  # different auth
        params={"q": state["question"], "count": 5}       # different params
    )
    data = response.json()
    return {"search_result": data["web"]["results"][0]["description"]}  # different response shape


# with mcp
def web_search(state: AgentState):
    result = mcp_client.call("web_search", query=state["question"])
    return {"search_result": result}

# if switching to brave change from:
{ "tool": "web_search", "provider": "tavily" }

# to:
{ "tool": "web_search", "provider": "brave" }
