# GoodzyCrawler

The **GoodzyCrawler** is a Python application designed to perform web crawling tasks. It uses a combination of libraries such as `requests`, `BeautifulSoup`, and `PyQt6` to fetch, parse, and display web content. Here's a high-level overview of its components and functionality:

## Key Components

1. **Imports**:  
   The script imports various libraries for HTTP requests, HTML parsing, GUI creation, DNS and WHOIS lookups, and more.

2. **WebCrawler Class**:  
   This class is responsible for the core crawling functionality. It uses a `ThreadPoolExecutor` to manage concurrent requests.  
   - It can respect `robots.txt` rules, extract various elements from web pages (like links, forms, cookies, etc.), and gather DNS and WHOIS information.  
   - It supports exporting results to CSV, JSON, and XML formats.

3. **CrawlerThread Class**:  
   A subclass of `QThread` that runs the WebCrawler in a separate thread to keep the GUI responsive.

4. **WebCrawlerGUI Class**:  
   This class creates a PyQt6-based GUI for user interaction.  
   - It includes tabs for input, logs, settings, and results.  
   - Users can input domains, configure crawling settings, and view results in a table format.  
   - It supports starting, stopping, pausing, and resuming the crawl process.

5. **Main Function**:  
   Initializes the PyQt application and sets up the main window with the WebCrawlerGUI.

## Features

- **Multi-threaded Crawling**: Uses multiple threads to crawl web pages concurrently.  
- **GUI Interface**: Provides a user-friendly interface for configuring and controlling the crawl process.  
- **Data Extraction**: Extracts and logs various data points from web pages, including links, forms, cookies, and more.  
- **Export Options**: Allows exporting crawl results to different file formats.  
- **DNS and WHOIS**: Optionally includes DNS and WHOIS information in the results.  
- **Settings Management**: Saves and loads user settings and domain lists for convenience.

## Usage

1. **Start the Application**: Run the script to launch the GUI.
2. **Configure Settings**: Use the settings tab to configure crawl depth, number of threads, user-agent, etc.
3. **Input Domains**: Add domains manually or upload from a file.
4. **Control Crawling**: Start, stop, pause, or resume the crawling process using the provided buttons.
5. **View and Export Results**: Check the results in the GUI and export them if needed.

This script is a comprehensive tool for web crawling, designed to be both powerful and user-friendly, with a focus on flexibility and extensibility.
