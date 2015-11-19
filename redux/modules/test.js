const TEST = 'rent-keepr/test/TEST';

let initialState = {clicks: 1};

export default function reducer(state = initialState, action = {}) {
  switch (action.type) {
    case TEST:
      clicks = state.clicks + 1;
      return {...state, clicks};
    default: return state;
  }
}

export function addClick() {
  return { type: test };
}
