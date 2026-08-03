const React = require("react");

module.exports = function Link(props) {
  const { children, ...anchor } = props;
  return React.createElement("a", anchor, children);
};
