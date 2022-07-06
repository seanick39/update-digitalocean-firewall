#ifndef UPDATE_FIREWALLS__UTILS_H
#define UPDATE_FIREWALLS__UTILS_H

#include <iostream>
#include <ranges>
#include <string>
#include <vector>

template <typename T> int fail(const T &t) {
  std::cerr << t;
  return EXIT_FAILURE;
}
template <typename T, typename... Args>
int fail(const T &t, const Args &...args) {
  std::cerr << t;
  return fail(args...);
}

template <typename T> void info(const T &t) { std::cout << t; }

template <typename T, typename... Args>
void info(const T &t, const Args &...args) {
  std::cout << t;
  info(args...);
}

template <typename T>
void info(const std::vector<T> &t) {
  info("[ \t");
  for (const T &val : t) {
    info("\"", val, "\", ");
  }
  info("] \n");
}
#endif // UPDATE_FIREWALLS__UTILS_H
