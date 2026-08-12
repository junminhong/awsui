"""Textual CSS shared by the primary awsui dashboard."""

DASHBOARD_CSS = """
Screen {
    layout: vertical;
    background: $background;
    color: $text;
}
#top-bar {
    height: 3;
    padding: 0 2;
    align-vertical: middle;
    background: $background;
    border-bottom: solid $border;
}
#brand {
    width: auto;
    color: $text;
    text-style: bold;
    margin-right: 2;
}
#breadcrumb { width: 1fr; color: $text-muted; }
#product-label { width: auto; color: $text-muted; }
#dashboard { height: 1fr; layout: horizontal; }
#context-pane {
    width: 34%;
    min-width: 26;
    max-width: 46;
    padding: 1 1 0 1;
    border-right: solid $border;
    background: $background;
}
#environment-heading {
    height: 2;
    margin: 0 1;
    color: $text-muted;
    text-style: bold;
}
#context-list {
    height: 1fr;
    border: none;
    background: $background;
}
#context-list > ListItem {
    height: 3;
    padding: 0 1;
    border-left: thick transparent;
    background: transparent;
}
#context-list > ListItem.-highlight {
    border-left: thick $primary;
    background: $panel;
    color: $text;
}
#detail-pane {
    width: 1fr;
    padding: 1 2;
    background: $background;
}
#detail-content {
    height: 1fr;
    padding: 2 3;
    background: $surface;
}
#action-bar {
    height: 2;
    padding: 0 1;
    align-vertical: middle;
    background: $surface;
    border-top: solid $border;
    scrollbar-size: 0 0;
}
#action-bar Button {
    width: auto;
    min-width: 0;
    height: 1;
    padding: 0 1;
    border: none;
    background: transparent;
    color: $text-muted;
    text-style: none;
}
#action-bar Button:hover, #action-bar Button:focus {
    background: $panel;
    color: $text;
}
#verify, #launch { color: $text-primary; }
#initialize { color: $text-primary; }
#action-bar Button:disabled {
    display: none;
}
"""


INITIALIZATION_CSS = """
InitializationScreen {
    layout: vertical;
    background: $background;
    color: $text;
}
#init-header {
    height: 3;
    padding: 0 2;
    align-vertical: middle;
    border-bottom: solid $border;
    background: $background;
}
#init-brand {
    width: auto;
    margin-right: 2;
    color: $text;
    text-style: bold;
}
#init-heading { width: 1fr; color: $text; text-style: bold; }
#init-path { width: auto; color: $text-muted; }
#init-progress {
    height: 2;
    padding: 0 2;
    color: $text-muted;
    background: $surface;
    border-bottom: solid $border;
}
#init-scroll { height: 1fr; }
.init-step {
    width: 1fr;
    height: auto;
    margin: 2 4;
    padding: 1 2;
    background: $surface;
    border: solid $border;
}
.init-title { height: 2; color: $text; text-style: bold; }
.init-help { height: auto; margin-bottom: 1; color: $text-muted; }
.init-label { height: 1; margin-top: 1; color: $text-muted; }
.init-error { height: auto; margin-top: 1; color: $text-error; }
.init-actions {
    height: 3;
    margin-top: 1;
    align-horizontal: right;
    align-vertical: middle;
}
.init-actions Button, .init-inline-actions Button {
    width: auto;
    min-width: 9;
    height: 1;
    margin-left: 1;
    padding: 0 1;
    border: none;
    background: transparent;
    color: $text-muted;
}
.init-actions Button:hover, .init-actions Button:focus,
.init-inline-actions Button:hover, .init-inline-actions Button:focus {
    background: $panel;
    color: $text;
}
.init-primary { color: $text-primary; }
.init-primary:hover, .init-primary:focus { background: $primary-muted; }
.init-danger { color: $text-error; }
.init-inline-actions { height: 3; align-horizontal: right; }
#init-profile-list, #init-method-list, #init-review-list {
    height: 9;
    margin-top: 1;
    border: solid $border;
    background: $background;
}
#init-profile-list:focus, #init-method-list:focus, #init-review-list:focus,
InitializationScreen Input:focus {
    border: tall $primary;
}
InitializationScreen Input { margin-bottom: 1; }
#init-protected { margin: 1 0; }
#init-auth-spinner { height: 3; color: $text-primary; }
#init-auth-status { height: auto; margin-bottom: 1; color: $text; }
#init-auth-log {
    height: 10;
    padding: 0 1;
    border: solid $border;
    background: $background;
    color: $text-muted;
}
#init-review-detail {
    height: auto;
    min-height: 6;
    margin-top: 1;
    padding: 1;
    background: $background;
    color: $text;
}
#init-access-warning { height: auto; margin-top: 1; color: $text-warning; }
"""
